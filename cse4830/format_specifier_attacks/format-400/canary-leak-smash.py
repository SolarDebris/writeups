#!/usr/bin/env python
from pwn import *

e = ELF("./format-400")
p = process('./format-400')

p.sendline("foo")
p.sendline(b'A'*100)
p.interactive()
