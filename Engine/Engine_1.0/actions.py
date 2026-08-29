from main import * 
from pwn import *
from argparse import Namespace


BUFFER_SIZE=0x78
STACK_SIZE=0x78


def binary(args: Namespace):
    args.proc = process(args.binary)

def debug_shellcode(args: Namespace):
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


def debug_program(args: Namespace):
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


def strace(args: Namespace):
    proc_argv = ["strace", args.binary]
    if args.strace_root:
        proc_argv.insert(0, "sudo")
    with process(proc_argv) as proc:
        if args.payload and args.payload_mod:
            args.payload_mod.send_in_payload(args.payload, proc)
        elif proceed("Send in the shellcode to the straced program?"):
            proc.send(args.shellcode_asm)


def objdump(args: Namespace):
    print(disasm(args.shellcode_asm))


def buff_size(args: Namespace):
    if args.buff_size < 0:
        args.buff_size = BUFFER_SIZE
    return args.buff_size


def stack_size(args: Namespace):
    if args.stack_size < 0:
        args.stack_size = STACK_SIZE
    return args.stack_size


def shellcode(args: Namespace):
    if args.shellcode != '\x00':
        filename = args.shellcode
        if args.shellcode.isdigit():
            filename = f"shellcode{args.shellcode}.s"
        update_shellcode(args, open(filename, "rb").read().decode())
    else:
        update_shellcode(args, binsh)


def payload(args: Namespace):
    if args.payload.rfind('.py') != -1:
        args.payload_mod = get_module(args.payload)

        if args.canary is not None:
            if args.canary == '':
                args.canary = args.payload_mod.get_canary(args)
            else:
                args.canary = int(args.canary, 16)
                args.canary = p64(args.canary)
            print(f'Binary canary: {args.canary}')

        try:
            args.payload = args.payload_mod.get_payload(args, args.proc)
        except AttributeError as _:
            print(_)
            args.payload = get_payload_manually(args)
    else:
        args.payload_mod = None
        args.payload = get_payload_manually(args)


