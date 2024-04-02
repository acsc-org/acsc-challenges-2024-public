from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

import os

flag = b"ACSC{___REDACTED___}"

def strongest_mask(seed, l):
  return b"\x01"*l

def strongest_random(l):
  x = bytes_to_long(os.urandom(1)) & 0b1111
  return long_to_bytes(x) + b"\x00"*(l-1)

f = open("strongest_OAEP.txt","w")

key = RSA.generate(2048,e=13337)

c_buf = -1

for a in range(2):
  OAEP_cipher = PKCS1_OAEP.new(key=key,randfunc=strongest_random,mgfunc=strongest_mask)

  while True:
    c = OAEP_cipher.encrypt(flag)
    num_c = bytes_to_long(c)
    if c_buf == -1:
      c_buf = num_c
    else:
      if c_buf == num_c:continue
    break

  f.write("c: %d\n" % num_c)
  f.write("e: %d\n" % key.e)
  f.write("n: %d\n" % key.n)

  OAEP_cipher = PKCS1_OAEP.new(key=key,randfunc=strongest_random,mgfunc=strongest_mask)
  dec = OAEP_cipher.decrypt(c)
  assert dec == flag

  # wow, e is growing!
  d = pow(31337,-1,(key.p-1)*(key.q-1))
  key = RSA.construct( ((key.p * key.q), 31337, d) ) 

