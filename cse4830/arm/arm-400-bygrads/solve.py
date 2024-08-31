enc1 = [0x7d, 0x29, 0x28, 0x74, 0x73, 0x75, 0x77, 0x2a, 0x78, 0x73, 0x75, 0x24, 0x76, 0x79, 0x74, 0x73]

enc2 = [0x2b, 0x7b, 0x7b, 0x79, 0x72, 0x7a, 0x78, 0x76, 0x7a, 0x77, 0x28, 0x79, 0x77, 0x75, 0x77, 0x77]


enc1 = reversed(enc1)
enc2 = reversed(enc2)

maybe = ['6','1','0', 'd','c','e','8', '2', '9', 'c', 'e', '4', 'f', 'a', 'd','c']
test1 = []
#test2 = ['0', '1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
test2 = []
flagmaybe = "" 

for i in enc1:
    test1.append(chr((i-3)  ^ 0x43))

for i in enc2:
    test2.append(chr((i + 4) ^ 0x4e))



for i, j in zip(test1, test2):
    flagmaybe += j + i
print(test1,test2)
print(flagmaybe)
print("".join(reversed(flagmaybe)))
