from pwn import *


vm = open("./not_another_vm.prog", "rb").read()


log.info(f"VM {vm}")

enc_even = b""
enc_odd = b""

diff = b""

pos = 0

for i in range(0, len(vm), 4):
    instr = vm[i:i+4]

    value = instr[0:2]
    opcode = instr[2:4]
    
    if opcode == b"\x00\x01":
        if pos % 2 == 0:
            enc_even += value
        else:
            enc_odd += value
        pos += 1

    log.info(f"Instr {instr}, Opcode {opcode}, Value {value}")

#enc_even = enc_even.replace(b"\x00",b"")
#enc_odd = enc_odd.replace(b"\x00",b"")

print(f"Enc Even {enc_even}, Enc Odd {enc_odd}")
print(f"Enc Even {len(enc_even)}, Enc Odd {len(enc_odd)}")

for i in range(len(enc_even)):
    diff += (int(enc_odd[i]) - int(enc_even[i])).to_bytes()

diff = diff.replace(b"\x00",b"")
print(f"Diff {diff}")

open("./solve", "wb").write(diff)
