from Crypto.Util.number import *
from concurrent.futures import ProcessPoolExecutor

is_hgcd = True

c = []
e = []
count = 0

with open('strongest_OAEP.txt') as f:
    for line in f:
       if count%3 == 0:
         c.append(int(line.split("c: ")[1]))
       elif count%3 == 1:
         e.append(int(line.split("e: ")[1]))
       else:
         n = int(line.split("n: ")[1])
       count += 1

print(c)
print(e)
print(n)

def related_message_attack_half_gcd(c1, c2, diff, e1, e2, n):
    PR.<x> = PolynomialRing(Zmod(n))
    f1 = x^e1 - c1
    f2 = (x+diff)^e2 - c2

    g = PR(f1._pari_with_name('x').gcd(f2._pari_with_name('x')))  # from https://furutsuki.hatenablog.com/entry/2023/06/20/131133
    ans = -g.monic()[0]
    return Integer(ans)

def related_message_attack_gcd(c1, c2, diff, e1, e2, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e1 - c1
    g2 = (x+diff)^e2 - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

def attack(diff):
   if is_hgcd:
     print("Half GCD")
     res = related_message_attack_half_gcd(c[0], c[1], diff<<(254*8), e[0], e[1], n)
   else:
     print("GCD")
     res = related_message_attack_gcd(c[0], c[1], diff<<(254*8), e[0], e[1], n)
   return res

for a in range(-15,16):
  res = attack(a)
  buf = hex(res)
  print(a,buf)
  if "010101010101" in buf:
      x = int(buf,16) ^^ int("01"*256,16)
      print(long_to_bytes(x))
      exit()

