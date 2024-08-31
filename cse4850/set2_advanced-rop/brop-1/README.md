# brop-1

**Category** : set2: advanced-rop
**Points** : 244

```python
from pwn import * 
p=remote("cse4850-brop-1.chals.io", 443, ssl=True, sni="cse4850-brop-1.chals.io")
p.interactive()
```



