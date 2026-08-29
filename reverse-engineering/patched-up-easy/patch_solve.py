#!/bin/python

from pwn import *

offset = int('28e1', 16)
val    = b'\x90\x90\x90\x90\xb8'

for i in range(0, len(val)):
    print(hex(offset))
    print(hex(val[i]))
    offset += 1
