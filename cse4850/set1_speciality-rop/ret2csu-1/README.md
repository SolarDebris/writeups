# ret2csu-1

**Category** : set1: speciality-rop
**Points** : 304

```python
from pwn import * 
p=remote("cse4850-ret2csu-1.chals.io", 443, ssl=True, sni="cse4850-ret2csu-1.chals.io")
p.interactive()
```

## Files : 
 - [chal.bin](./chal.bin)
 - [libhelper.so](./libhelper.so)


