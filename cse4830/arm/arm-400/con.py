from pwn import *


p = remote("cse4830-arm-400.chals.io", 443, ssl=True, sni="cse4830-arm-400.chals.io")

p.recvuntil(b'Password >>>')
p.send(b'vKr_oAQE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
p.interactive()
