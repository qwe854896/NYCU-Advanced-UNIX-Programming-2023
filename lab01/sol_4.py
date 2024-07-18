#!/usr/bin/env python3
from pwn import *


def get_ip():
    # url = "http://ipinfo.io/ip"
    # ip = wget(url)

    r = remote("ipinfo.io", 80)
    r.send(b"GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\n\r\n")
    r.recvuntil(b"\r\n\r\n")
    ip = r.recv()
    r.close()
    return ip


print(get_ip().decode("utf-8"))
