#!/bin/python

from pwn import *

offset = int('232a', 16)
val    = b'38'

for i in range(0, len(val)):
    print(hex(offset))
    print(hex(val[i]))
    offset += 1
