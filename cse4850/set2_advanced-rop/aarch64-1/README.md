# aarch64-1

**Category** : set2: advanced-rop
**Points** : 356

```python
from pwn import * 
p=remote("cse4850-aarch64-1.chals.io", 443, ssl=True, sni="cse4850-aarch64-1.chals.io")
p.interactive()
```

## Files : 
 - [chal.bin](./chal.bin)


