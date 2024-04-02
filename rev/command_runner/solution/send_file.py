from pwn import *
import sys

if len(sys.argv) < 4:
    print("How to use: python3 solve.py [HOST] [PORT] [filename]")
    exit(0)

data = open(sys.argv[3], 'rb').read()
r = remote(sys.argv[1], sys.argv[2])

r.sendlineafter(b'Length: ', str(len(data)).encode())
r.sendafter(b'Data: \n', data)

r.interactive()