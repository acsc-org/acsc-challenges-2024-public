from pwn import *
import sys

if len(sys.argv) < 3:
    print("How to use: python3 solve.py HOST PORT")
    exit(0)

data = open('cat_flag_star.png', 'rb').read()
print(len(data))
r = remote(sys.argv[1], sys.argv[2])

r.sendlineafter(b'Length: ', str(len(data)).encode())
r.sendafter(b'Data: \n', data)

r.interactive()