#!/bin/python

from pwn import *
import context as cnt
import debug_actions
import IPython
import importlib
import argparse
import sys
import os

context.arch = 'amd64'

BUFFER_SIZE=0x78
STACK_SIZE=0x78


debug_actions_list = [
    ['debug program', debug_actions.debug_program],
    ['debug shellcode', debug_actions.debug_shellcode],
    ['strace', debug_actions.strace],
    ['main', debug_actions.main_exe],
]


def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-v', "--verbose", action='store_true')
    parser.add_argument('-q', "--dont_ask" , action='store_true')
    parser.add_argument('-ll', "--log-level", default='warn', type=str)

    parser.add_argument('-sc', "--shellcode", nargs='?', const='\x00', type=str)
    parser.add_argument('-od', "--objdump" , action='store_true')
    parser.add_argument('-bs', "--buff-size" , type=int, default=BUFFER_SIZE)
    parser.add_argument('-ss', "--stack-size" , type=int, default=STACK_SIZE)
    parser.add_argument('-c', "--canary" , nargs='?', const='\x00', type=str)
    parser.add_argument('-p', "--payfile", nargs='?', const='\x00', type=str)

    parser.add_argument('-sr', "--strace-root", action='store_true')

    args = parser.parse_args()
    args_dict = vars(args)

    context = cnt.Context(args_dict)


    while True:
        for idx,pair in enumerate(debug_actions_list):
            print(f"{idx}- {pair[0]}.")

        choice = input(f"Enter 0..{len(debug_actions_list)-1}: ")
        choice = int(choice) if len(choice) else 0

        debug_actions_list[choice][1](context)

        if context.dont_ask or cnt.proceed("Exit?",invert=True):
            break
        if not context.dont_ask and cnt.proceed("Restart context state?"):
            context = cnt.Context(args_dict)
    

if __name__ == '__main__':
    main()
