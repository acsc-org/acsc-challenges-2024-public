from z3 import *

title_upper = int.from_bytes(b"ACSC", 'little')
title_lower = int.from_bytes(b"2024", 'little')

passcode = [ BitVec("passcode%s" % (i), 32) for i in range(4) ]

s = Solver()

s.add(passcode[0]^passcode[1]==title_upper)
s.add(passcode[2]^passcode[3]==title_lower)

def gen_checksum(key_a, key_b):
    return (( ((key_a >> 24) & 0xff) | ((key_a >> 8) & 0xff00) | ((key_a << 16) & 0xffff0000) ) ^ key_b) & 0xffffffff

checksum1 = gen_checksum(passcode[0], passcode[1])
checksum2 = gen_checksum(passcode[1], passcode[0])
checksum3 = gen_checksum(passcode[2], passcode[3])
checksum4 = gen_checksum(passcode[3], passcode[2])

s.add(checksum1 == 0x252d0d17)
s.add(checksum2 == 0x253f1d15)
s.add(checksum3 == 0xbea57768)
s.add(checksum4 == 0xbaa5756e)


s.add(passcode[1]&0xff == 0xd8)
s.add(passcode[3]&0xff == 0x7d)


print(s.check())

ans1 = (s.model()[passcode[0]].as_long())
ans2 = (s.model()[passcode[1]].as_long())
ans3 = (s.model()[passcode[2]].as_long())
ans4 = (s.model()[passcode[3]].as_long())


print(hex(ans1), hex(ans2), hex(ans3), hex(ans4))


# Trigger assertion if the key is wrong
assert (ans1 == 0xcfe7a999) 
assert (ans2 == 0x8cb4ead8)
assert (ans3 == 0x15d89f4f)
assert (ans4 == 0x21eaaf7d)
