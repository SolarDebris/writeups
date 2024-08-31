# oob-1

**Category** : set3: type-vulns
**Points** : 304

```python
from pwn import * 
p=remote("cse4850-oob-1.chals.io", 443, ssl=True, sni="cse4850-oob-1.chals.io")
p.interactive()
```

## Files : 
 - [chal.bin](./chal.bin)


