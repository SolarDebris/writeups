# intro-100

**Category** : assembly review
**Points** : 100

The challenges are created using **SNI**, its easiest enough to connect to them using [pwntools](https://github.com/Gallopsled/pwntools) scripts. The first challenge just prints a flag. Verify that you can connect to it and return the flag. 

```python
from pwn import * 
p=remote("cse4830-intro-100.chals.io", 443, ssl=True, sni="cse4830-intro-100.chals.io")
p.interactive()
```



