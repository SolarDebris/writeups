# Tcache Pointer Mangling

In this program, our main bug is that we have an 
edit/view after free. This can allow us to get libc leaks and other
interesting data. It also allows us to change and modify freed chunks


# Getting the xor value

Since each pointer is mangled with a value we need to first find that
value. Also since the end of a linked list is zero it means that
if we find that value that is the value that we can use to 
create our own mangled pointers

