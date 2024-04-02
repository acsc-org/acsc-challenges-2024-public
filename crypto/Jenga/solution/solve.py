from pwn import *
from Jenga import *
import itertools
import sys

if len(sys.argv) < 3:
    r = process(['python3', 'task.py'])
else:
    r = remote(sys.argv[1], sys.argv[2])

pts, cts = [], []

lines = []

for i in range(256):
    ip = [i] + [0] * 8
    Jenga.hori_inv(ip)
    lines.append(bytes(ip).hex().encode())
    pts.append(bytes(ip))

r.sendlines(lines)
cts = r.recvlines(256)

query_answers = []

for i in range(256):
    cts[i] = bytes.fromhex(cts[i].split()[-1].strip().decode())
    v = list(cts[i])
    Jenga.vert_inv(v)
    Jenga.sbox_inv(v)
    Jenga.hori_inv(v)
    query_answers.append(v)

keyc = [[] for _ in range(9)]

for loc in range(9):
    for test in range(256):
        res = 0
        for i in range(256):
            res ^= SBOX_inv[test ^ query_answers[i][loc]]
        if res == 0:
            keyc[loc].append(test)

for subkey in itertools.product(*keyc):
    subkey = list(subkey)
    Jenga.hori(subkey)
    subkey_rev = subkey[::-1]

    for _ in range(36):
        subkey_rev.append(SBOX_inv[subkey_rev[-9]] ^ subkey_rev[-8])
    
    final_key = bytes(subkey_rev[::-1][:9])
    cipher = Jenga(final_key)

    for pt, ct in zip(pts, cts):
        res = cipher.encrypt(pt)
        if ct != res:
            break
    else:
        print("FOUND KEY")
        break

r.recvuntil(b'ct: ')
ct = bytes.fromhex(r.recvline().strip().decode())
pt = cipher.decrypt(ct)
r.sendlineafter(b'pt? ', pt.hex().encode())

r.interactive()
