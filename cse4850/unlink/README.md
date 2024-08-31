# Unlink Challenge

For this challenge we are given a create, edit, view and free 
functions. The create can only create 5 chunks of size 0xa0 and 
the edit function can do a one byte overwrite. The chunk list 
is also on the heap and writable. 

## Getting Heap Leak

If we mess around a bit we can see that if we view something
that hasn't been allocated it will print out an error message
with that chunks address. Using this we can get a heap leak.

## Getting Write Primitive

For getting the write primitive we can do an unsafe unlink.
The unlinking process is when chunks are consolidated together.
We can trigger two chunks to be consilidated by freeing one chunk
that has an allocated chunk in between this and the top chunk then freeing
that chunk. So our plan is to create a fake chunk that has an allocated chunk
in between this and create fake forwards and backwards pointers.

One of my main problems and gripes with this challenge was that I wasn't freeing
the last chunk like I thought I was and was freeing the second to last chunk
because the program started indexing at 1. 

I also came into a libc check when this error was printed. Corrupted doubly linked list.
Which checked if P->fd->bk == P and P->bk->fd == P. To make sure that it worked I made it
so that the fd from my fake chunk had a bk that was equal to it and that the bk had an fd that
was equal to the pointer. 


## Getting a libc leak

To get a libc leak we can edit the 4th chunk which is now our chunk list to 
point to the free got entry. Then we can view the first chunk which is pointed
to the free got entry to get our libc leak.

## Getting a Shell

Now we can overwrite free with system. But there is a problem, the 0xa overwrites the first byte of the
puts got entry which gets called in our delete function. So we need to overwrite the puts got entry with 
puts. Then the next time we call free we will call system. So what I did is overwrite the second value on the chunk
list to point to /bin/sh and then deleted the second item. This allowed me to get a shell.



