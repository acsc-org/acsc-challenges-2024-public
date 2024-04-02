import subprocess
import time
import threading

N = 3
known = ''

for _ in range(len(known), 10):
    t = []

    for digit in range(10):
        print('.', end='', flush=True)
        avr = 0.0
        pin = known + str(digit) + '0'*10
        for _ in range(N):
            p = subprocess.Popen(
                ["/home/user/chall"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            s = time.time()
            out, err = p.communicate(pin.encode())
            e = time.time()
            avr += e - s
        t.append(avr / N)
        print(t)

    known += str(t.index(max(t)))
    print(known)
