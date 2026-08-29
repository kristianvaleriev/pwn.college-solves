#!/bin/python

from pwn import * 

PROGRAM="/challenge/now-you-got-it-easy"

elf = ELF(PROGRAM)

proc = process(PROGRAM)
proc.readuntil(b"The array starts at 0x")
leak = int(proc.readuntil(',')[:-1], 16)

print(f"{hex(leak)}; puts: {elf.got['puts']}")
print(elf.got)

print ()
