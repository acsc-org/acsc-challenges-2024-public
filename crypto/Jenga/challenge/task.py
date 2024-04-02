from Jenga import Jenga
import os
import signal

TIMEOUT = 30

key = os.urandom(9)
cipher = Jenga(key)

def timeout(signum, frame):
    print("Timeout!!!")
    signal.alarm(0)
    exit(0)

signal.signal(signal.SIGALRM, timeout)
signal.alarm(TIMEOUT)

for i in range(256):
    pt = bytes.fromhex(input("> ").strip())
    ct = cipher.encrypt(pt)
    print(f"ct: {ct.hex()}")

pt = os.urandom(9)
ct = cipher.encrypt(pt)
print(f"ct: {ct.hex()}")
user_pt = bytes.fromhex(input("pt? ").strip())

if pt == user_pt:
    print("Congratz!")
    flag = open('flag', 'r').read()
    print(f"Here is the flag: {flag}")
else:
    print("Wrong :(")
