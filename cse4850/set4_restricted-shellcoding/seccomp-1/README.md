# seccomp-1

**Category** : set4: restricted-shellcoding
**Points** : 496

```python
from pwn import * 
p=remote("cse4850-seccomp-1.chals.io", 443, ssl=True, sni="cse4850-seccomp-1.chals.io")
p.interactive()
```

## Files : 
 - [chal.bin](./chal.bin)


