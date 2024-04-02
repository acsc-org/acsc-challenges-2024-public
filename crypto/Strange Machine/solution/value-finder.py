from sage.all import *

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
bn254 = 21888242871839275222246405745257275088696311157297823662689037894645226208583

delta = (2 * bn254 * (1 << 256)) % p

POL = PolynomialRing(GF(p), 'x')
x = POL.gen()

x_new_num = 9 * (x * x + delta) * (x * x + delta) - 8 * x * (x ** 3 + 7)
x_new_den = 4 * (x ** 3 + 7)

x_new_num **= 3
x_new_den **= 3

y_new_num = 3 * (x * x + delta) * (12 * x * (x ** 3 + 7) - 9 * (x * x + delta) ** 2) - 8 * (x ** 3 + 7) ** 2
y_new_num **= 2
y_new_den = 64 * (x ** 3 + 7) ** 3

res = x_new_num * y_new_den - x_new_den * y_new_num
x = int(res.roots()[0][0])
print(x)

orig = (x * x) % p
renew = (orig + delta) 
quot = ((x * x - renew) * inverse_mod(p, bn254 << 256)) % (bn254 << 256)

print(int(quot) / (1 << 256))
print(renew / (1 << 256))
print((x * x - p * quot - renew) % (bn254 << 256))