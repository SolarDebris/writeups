# brop-2

**Category** : set2: advanced-rop
**Points** : 998

Welcome to the Opera. The lights are off, go pwning blindly. 

```python

from pwn import * 

OFFSET_MIN = 1
OFFSET_MAX = 100

STOP_GADGET_MIN = 0x400849
STOP_GADGET_MAX = STOP_GADGET_MIN+0x100

BROP_GADGET_MIN = 0x4009e6
BROP_GADGET_MAX = BROP_GADGET_MIN + 0x100

PLT_MIN = 0x4006c0
PLT_MAX = PLT_MIN +0x100

DATA_MIN = 0x400a30
DATA_MAX = DATA_MIN + 0x100

p=remote("cse4850-brop-2.chals.io", 443, ssl=True, sni="cse4850-brop-2.chals.io")
p.interactive()
```



