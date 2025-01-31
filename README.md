# writeups
A collection of writeups for challenges that I've done that I thought were interesting



## PWN Tricks
Here below is a list of simple tricks/problems i have when pwning

### Stack Buffer Overflows

*movaps* - when running your exploit if you end up crashing in libc with an instruction that
ends in aps, then that means that your stack is not aligned by 0x10 bytes. to fix this 
add a single ret into your rop chain before calling the libc function.

### Mitigations 

*pie* - a trick for leaking pie is to use the __dso_handle ptr which is a ptr to itself.
this can be useful if you have some sort of an array out of bounds or format leak


### Heap Exploitation

#### Leaking libc
To leak libc, you can create an unsortedbin chunk and then free it. If you 
view it with no other chunks in the unsortedbin you can see a ptr to libc. If you 
want to reallocate it, then you need to change the is_mmapped field to on in the chunk.

#### Leaking Heap
This one you can view any freed chunk, or use the same unsortedbin trick with more chunks
in the unsortedbinss



### Pattern Recognition 
Sometimes pattern recognition is important to find vulnerabilities and weird things with the
program.


* if the most significant byte is 0x7f (127), it is close to the highest signed value 0x7fffffff (highest int size)
without being negative.
* a canary will be 16 bytes long and the least significant byte will be 0x00



### Kernel Exploitation

