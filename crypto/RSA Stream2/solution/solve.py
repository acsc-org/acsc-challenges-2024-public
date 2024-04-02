from fractions import Fraction
from math import ceil

n = int(open("output.txt").read().strip().split(" = ")[1])

ciphertext = open("chal.py.enc", "rb").read()
plaintext = open("chal_redacted.py", "rb").read()

p = 0
i = 0
def getnextbit():
    global p, i

    bit = (( ciphertext[p] >> i ) & 1) ^ ((plaintext[p] >> i) & 1)
    i += 1
    if i == 8:
        i = 0
        p += 1
    return bit

ok, ng = 0, n
while abs(ng - ok) > 1:
    mid = Fraction(ok + ng, 2)
    if getnextbit() == 1:
        ok = mid
    else:
        ng = mid

m = int(ceil(ok))
text = []
for b in ciphertext:
    o = 0
    for i in range(8):
        m = 2*m
        bit = ((b >> i) & 1) ^ (m % n % 2)
        o |= bit << i
    text.append(o)
print(bytes(text).decode())
