from pwn import * 
import context as c
import IPython

context.arch = 'amd64'

def main_exe(args):
    if args.proc is not None and c.proceed("Restart proc?"):
        args.start_proc()
    if args.proc is None:
        args.start_proc()

    if args.payload:
        args.get_payload()
        args.send_payload()
    else:
        IPython.embed(header="main")
        return 

    try:
        args.proc.recvuntil(FLAG)
        print('Flag: ' + str(args.proc.recvline()))
        if proceed("Exit?"):
            exit(0)
    except: 
        pass

    args.proc.interactive()
    

def debug_shellcode(args):
    if not args.shellcode:
        print("No shellcode to debug!")
        return 

    while True:
        if c.proceed("Add an int3 instruction at the beginning? "):
            update_shellcode(args, '\tint3\n' + args.shellcode_str)
            proc = gdb.debug_assembly(args.shellcode_str)
        IPython.embed(header="Debugging shellcode")

        if c.proceed("Break the loop?", invert=True):
            break
        proc.close()


def debug_program(args):
    while True:
        args.start_proc(True)

        if args.payfile:
            payload = args.get_payload()
            if args.canary:
                args.canary = p64(int(input('Enter canary: '), 16))
                print('Canary: ' + str(args.canary))
            
            args.send_payload()

        elif args.shellcode      \
        and  not args.dont_ask   \
        and  c.proceed("Send in the shellcode to the program in debugging?"):
             proc.send(args.shellcode_asm)

        IPython.embed(header="Debugging program")
        if not c.proceed("Restart?"):
            break


def strace(args):
    proc_argv = ["strace", args.binary]
    if args.strace_root:
        proc_argv.insert(0, "sudo")
    with process(proc_argv) as proc:
        if args.payload and args.payload_mod:
            args.payload_mod.send_in_payload(args.payload, proc)
        elif c.proceed("Send in the shellcode to the straced program?"):
            proc.send(args.shellcode_asm)

