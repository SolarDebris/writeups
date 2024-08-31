# shellcode-1

**Category** : set4: restricted-shellcoding
**Points** : 496

I liked [odd_shell](https://github.com/sigpwny/UIUCTF-2022-Public/tree/main/pwn/odd_shell) from SigPwny/UIUCTF 2022 so much that I recompiled it as *even shell* for you. Also, I've put a container for you to debug. You can run it with ``docker run -ti tjoconnor/even-shellcode /bin/tmux``

```python
from pwn import * 
p=remote("cse4850-shellcode-1.chals.io", 443, ssl=True, sni="cse4850-shellcode-1.chals.io")
p.interactive()
```

## Files : 
 - [chal.bin](./chal.bin)


