from pwn import *


p = remote("cse4830-arm-300.chals.io", 443, ssl=True, sni="cse4830-arm-300.chals.io")
p.interactive()
