#!/bin/python

from pwn import *

offset = int('1f8f', 16)
val    = b'38'

print(hex(offset))
print(hex(val[0]))

offset = int('206e', 16)
print(hex(offset))
print(hex(val[0]))
