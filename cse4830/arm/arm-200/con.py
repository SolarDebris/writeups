from pwn import *



p = remote("cse4830-arm-200.chals.io", 443, ssl=True, sni="cse4830-arm-200.chals.io")
p.interactive()
