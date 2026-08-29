from pwn import *
import importlib
import debug_actions
import IPython


class Context:
    def __init__(self, args: dict):
        self.proc = None
        self.payload = None
        self.payload_mod = None
        self.shellcode_str = None
        self.shellcode_asm = None

        for key,val in args.items():
            setattr(self, key, val);
            if val:
                try:
                    getattr(Context, key)(self)
                except AttributeError as _:
                    pass


    @staticmethod
    def get_module(filename):
        if not os.path.exists(filename) or filename[-3:] != '.py':
            print('invalid filename in get_module()')
            exit(1)
        if filename.find('/') == -1:
            filename = './' + filename

        mod_basename = os.path.basename(filename)[:-3]
        spec   = importlib.util.spec_from_file_location(\
                                mod_basename, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        return module


    def get_payload_manually(self):
        self.payload = None
        IPython.embed(header='Specify payload manualy:')

        if self.payload is None:
            print('No payload given...')
        else:
            print(f"The specified payload: {args.payload}")

        return payload


    def start_proc(self, debug=False):
        if self.proc is process:
            rc = self.proc.poll()
            if rc is None:
                self.proc.kill()
            else:
                print("Process return code: " + str(rc))

        if debug:
            self.proc = gdb.debug(self.binary, gdbscript=\
                                  open('gdbscript', 'r').read(),
                                  aslr=False, setuid=False)
        else:
            self.proc = process(self.binary)


    def update_shellcode(self, shellcode: str):
        self.shellcode_str = shellcode
        self.shellcode_asm = asm(shellcode)

        if self.verbose:
            print("Updated shellcode: \n" + str(self.shellcode_str))
            print(f"Asm length: {len(self.shellcode_asm)} bytes\n")

    
    def objdump(self):
        print(disasm(self.shellcode_asm))


    def shellcode(self):
        if self.shellcode != '\x00':
            filename = self.shellcode
            if self.shellcode.isdigit():
                filename = f"shellcode{self.shellcode}.s"
            update_shellcode(self, open(filename, "rb").read().decode())
        else:
            update_shellcode(self, binsh)

    
    def conv_canary(self):
        self.canary = int(self.canary, 16)
        self.canary = p64(self.canary)


    def get_payload(self):
        if self.payfile.rfind('.py') != -1:
            self.payload_mod = Context.get_module(self.payfile)

            if self.canary is not None:
                if self.canary == '\x00':
                    try:
                        self.canary = self.payload_mod.get_canary(self)
                    except:
                        pass
                else:
                    conv_canary(self)
                print(f'Binary canary: {self.canary}')

            try:
                self.payload = self.payload_mod.get_payload(self, self.proc)
            except AttributeError as _:
                print("payload mod failed: " + str(_))
                self.payload = self.get_payload_manually()
        else:
            self.payload_mod = None
            self.payload = self.get_payload_manually()

            if canary != '\x00':
                conv_canary(self)

        return self.payload


    def send_payload(self):
        try:
            self.payload_mod.send_in_payload(self.payload, self.proc)
        except AttributeError as _:
            print("Got attribute error for send in payload. Sending manually")
            self.proc.send(self.payload)



def proceed(msg=None, invert=False):
    if msg is not None:
        print(msg)

    try:
        if not invert:
            return True if 'n' not in input("[Y/n]: ").lower() else False
        return False if 'y' not in input("[y/N]: ").lower() else True
    except KeyboardInterrupt as _:
        exit(0)
