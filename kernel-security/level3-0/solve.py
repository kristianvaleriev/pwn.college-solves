#!/bin/python

import os 
import sys
from pwn import * 

context.arch = 'amd64'


PASSWORD='wymrurvvrnogjvfm'
with open("/proc/pwncollege", 'w') as f:
    f.write(PASSWORD)

try:
    with open("/flag", 'r') as flag:
        print(flag.read())
except Exception as ex:
    print("Exception:: " + str(ex))

