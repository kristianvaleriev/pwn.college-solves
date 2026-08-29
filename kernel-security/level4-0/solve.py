#!/bin/python

import os 
import sys
import fcntl
from pwn import * 

context.arch = 'amd64'


IOCTL_CMD = 0x539
PASSWORD='qauajmtfmkgngtok'
fd = os.open("/proc/pwncollege", os.O_RDWR) 
fcntl.ioctl(fd, IOCTL_CMD, PASSWORD)

try:
    with open("/flag", 'r') as flag:
        print(flag.read())
except Exception as ex:
    print("Exception:: " + str(ex))

