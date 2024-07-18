#!/usr/bin/env python3

from pwn import *
from solpow import solve_pow
import base64


def get_conn():
    r = remote("140.113.213.213", 10681)
    solve_pow(r)
    return r


# 0123456789+*/
books = {
    " ┌───┐  │   │  │   │  │   │  └───┘ ": "0",
    "  ─┐      │      │      │     ─┴─  ": "1",
    " ┌───┐      │  ┌───┘  │      └───┘ ": "2",
    " ┌───┐      │   ───┤      │  └───┘ ": "3",
    " │   │  │   │  └───┤      │      │ ": "4",
    " ┌────  │      └───┐      │  └───┘ ": "5",
    " ┌───┐  │      ├───┐  │   │  └───┘ ": "6",
    " ┌───┐  │   │      │      │      │ ": "7",
    " ┌───┐  │   │  ├───┤  │   │  └───┘ ": "8",
    " ┌───┐  │   │  └───┤      │  └───┘ ": "9",
    "          │    ──┼──    │          ": "+",
    "         ╲ ╱     ╳     ╱ ╲         ": "*",
    "          •    ─────    •          ": "//",
}


def sol_chal(b64_enc):
    lines = base64.b64decode(b64_enc).decode().split("\n")

    chars = [""] * 7
    for line in lines:
        for i in range(7):
            chars[i] += line[i * 7 : i * 7 + 7]
        print(line)

    ans = ""
    for c in chars:
        print(books[c], end="")
        ans += books[c]

    ans = eval(ans)
    print(" = ", ans)

    return ans


def main():
    r = get_conn()

    r.recvuntil(b"Please complete the ")
    num_challenge = int(r.recvuntil(b" ").strip())
    print("num_challenge =", num_challenge)

    for _ in range(num_challenge):
        r.recvuntil(b": ")
        rst = r.recvuntil(b" = ?")[:-4].decode()
        ans = sol_chal(rst)
        r.sendline(str(ans))

    r.interactive()


if __name__ == "__main__":
    main()
    # sol_chal("IOKUjOKUgOKUgOKUgOKUkCAg4pSM4pSA4pSA4pSA4pSQICDilIzilIDilIDilIDilJAgICAgICAgICDilIzilIDilIDilIDilJAgIOKUjOKUgOKUgOKUgOKUkCAg4pSCICAg4pSCIAogICAgIOKUgiAg4pSCICAg4pSCICDilIIgICDilIIgICAg4pSCICAgIOKUgiAgIOKUgiAg4pSCICAg4pSCICDilIIgICDilIIgCiDilIzilIDilIDilIDilJggIOKUnOKUgOKUgOKUgOKUpCAg4pSc4pSA4pSA4pSA4pSkICDilIDilIDilLzilIDilIAgIOKUlOKUgOKUgOKUgOKUpCAgICAgIOKUgiAg4pSU4pSA4pSA4pSA4pSkIAog4pSCICAgICAg4pSCICAg4pSCICDilIIgICDilIIgICAg4pSCICAgICAgICDilIIgICAgICDilIIgICAgICDilIIgCiDilJTilIDilIDilIDilJggIOKUlOKUgOKUgOKUgOKUmCAg4pSU4pSA4pSA4pSA4pSYICAgICAgICAg4pSU4pSA4pSA4pSA4pSYICAgICAg4pSCICAgICAg4pSCIA==")
