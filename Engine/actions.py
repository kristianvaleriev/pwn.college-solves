import context
import main

context.arch = 'amd64'

def main_exe(args: Context):
    if not args.payload:
        if main.proceed("Send in just shellcode?"):
            args.proc.send(args.shellcode_asm)
        else:
            IPython.embed("main")
        return 

    if args.payload_mod:
        try:
            args.payload_mod.send_in_payload(args.payload, args.proc)
        except Exception as e:
            print(e + "\nSending payload automaticaly")
            args.proc.send(args.payload)
    else:
        args.proc.send(args.payload)
    

def debug_shellcode(args: Context):
    if not args.shellcode:
        print("No shellcode to debug!")
        return 

    while True:
        if proceed("Add an int3 instruction at the beginning? "):
            update_shellcode(args, '\tint3\n' + args.shellcode_str)
            proc = gdb.debug_assembly(args.shellcode_str)
        IPython.embed(header="Debugging shellcode")

        if proceed("Break the loop?", invert=True):
            break
        proc.close()


def debug_program(args: Context):
    while True:
        proc = gdb.debug(args.binary, gdbscript=open('gdbscript', 'r').read())
        if args.payload:
            if args.canary:
                args.canary = p64(int(input('Enter canary: '), 16))
                print('Canary: ' + str(args.canary))

            if args.payload_mod:
                payload = args.payload_mod.get_payload(args, proc)
                args.payload_mod.send_in_payload(payload, proc)
            else:
                get_payload_manually(args)

        elif args.shellcode and not args.dont_ask and \
           proceed("Send in the shellcode to the program in debugging?"):
            proc.send(args.shellcode_asm)

        IPython.embed(header="Debugging program")
        if proceed("Break the loop?", invert=True):
            break
        proc.close()


def strace(args: Context):
    proc_argv = ["strace", args.binary]
    if args.strace_root:
        proc_argv.insert(0, "sudo")
    with process(proc_argv) as proc:
        if args.payload and args.payload_mod:
            args.payload_mod.send_in_payload(args.payload, proc)
        elif proceed("Send in the shellcode to the straced program?"):
            proc.send(args.shellcode_asm)

