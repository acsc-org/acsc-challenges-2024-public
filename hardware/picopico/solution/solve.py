#!/usr/bin/env python3
import sys

if len(sys.argv) != 2:
    print(f'{sys.argv[0]} (firmware dump file)')
    exit(1)

with open(sys.argv[1], 'rb') as f:
    flash = f.read()

key = flash[0xff000 + 0x04:0xff000 + 0x04 + 43]
flag_enc = flash[0xff000 + 0x04 + 43:0xff000 + 0x04 + 43 + 43]

flag = bytes((
    kb ^ fb
    for kb, fb in zip(key, flag_enc)
)).decode()

print(flag)
