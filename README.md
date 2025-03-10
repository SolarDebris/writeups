# writeups
A collection of writeups for challenges that I've done that I thought were interesting

| Challenge  | Type |
|----------- |------|
| [No Handouts](buckeyectf_2024/no_handouts)| ret2libc, Seccomp |
| [Sailing The Sea](buckeyectf_2024/sailing_the_sea) | Read What Where |
| [Spaceman](buckeyectf_2024/spaceman) | RiscV ROP |
| [vip](csaw_2024/vip) | whitelist |
| [bop](dice_2023/bop) | seccomp ret2libc |
| [babyqemu](hitb-gsec-2017/babyqemu_upsolved) | QEMU Escape |
| [typop](idek_2023/typop) | FULL Green ROP Ret2CSU |
| [checksumz](irisctf_2025/checksumz_upsolved) | Linux Kernel Modprobe Path |
| [sus](lactf_2024/sus) | ret2libc |
| [flightscript](patriotctf_2024/flightscript) | heap largebins attack |
| [not another vm](patriotctf_2024/not_another_vm) | vm flag checker |
| [shellcrunch](patriotctf_2024/shellcrunch) | restricted shellcoding |
| [babyheap](pwncon/babyheap) | house of botcake |
| [lightftp](realworld_2023/lightftp) | race condition |
| [nolibc](sekai_2024/nolibc) | custom heap |
| [fallingrop](spaceheroes_2024/fallingrop) | ret2system |
| [fsop](spaceheroes_2024/fsop) | fsop |
| [helldivers](spaceheroes_2024/helldive) | custom canary, house of spirit |
| [mindmeld](spaceheroes_2024/mindmeld) | srop, ptrace |
| [ctf-simulator](sunshine_2022/simulator) | srand |
| [house-of-sus](sunshine_2023/house_of_sus) | house of force |
| [flock-of-birds](sunshine_2023/flock-of-birds) | custom canary |
| [heap01](sunshine_2024/heap01) | tcache per thread struct |
| [jungle](sunshine_2024/jungle) | tcache pointer mangling |
| [secure](sunshine_2024/secure) | house of force, seccomp |
| [321](sunshine_2024/321) | speed pwn |
| [pointers](tamuctf/pointers) | stack variable bof |
| [seashells](tamuctf/seashells) | shellcode |



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

