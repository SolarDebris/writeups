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
    return None

if __name__=="__main__":
    file = './ctf-simulator'

    p = start(file)
    p.recvuntil(b'[>]')
    p.sendline(b'A' * 20)
    leak = p.recvline().split(b" ")[2][20:]#.replace(b',',b'\x00')
    print(leak)
          

    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
