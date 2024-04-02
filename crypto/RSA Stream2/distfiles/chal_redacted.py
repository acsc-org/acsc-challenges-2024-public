from Crypto.Util.number import getPrime
import random
import re


p = getPrime(512)
q = getPrime(512)
e = 65537
n = p * q
d = pow(e, -1, (p - 1) * (q - 1))

m = random.randrange(2, n)
c = pow(m, e, n)

text = open(__file__, "rb").read()
ciphertext = []
for b in text:
    o = 0
    for i in range(8):
        bit = ((b >> i) & 1) ^ (pow(c, d, n) % 2)
        c = pow(2, e, n) * c % n
        o |= bit << i
    ciphertext.append(o)


open("chal.py.enc", "wb").write(bytes(ciphertext))
redacted = re.sub("flag = \"ACSC{(.*)}\"", "flag = \"ACSC{*REDACTED*}\"", text.decode())
open("chal_redacted.py", "w").write(redacted)
print("n =", n)

# flag = "ACSC{*REDACTED*}"
