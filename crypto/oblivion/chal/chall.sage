import random
from hashlib import sha512
from base64 import b64encode, b64decode
import signal

n = 64
n_bytes = n // 8
l = 128
l_bytes = l // 8
F2n.<ε> = GF(2**n)

def bytes2bits(b):
    return list(map(int, "".join([format(x, "08b") for x in b])))

def bits2bytes(b):
    return bytes([int("".join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8)])

def xor(a, b):
    return bytes([x ^^ y for x, y in zip(a, b)])

def transpose(M):
    T = [[0] * len(M) for _ in range(len(M[0]))]
    for i in range(len(M)):
        for j in range(len(M[0])):
            T[j][i] = M[i][j]
    return T
    
def recv_bytes(msg, n=0):
    return b64decode(input(msg)[:2 * n]).ljust(n, b"\x00")

class PRNG:
    def __init__(self):
        self.hasher = sha512(random.randbytes(32))
        self.pending = b""

    def randbytes(self, nbytes):
        while len(self.pending) < nbytes:
            self.hasher.update(random.randbytes(8))
            self.pending += self.hasher.digest()
        self.pending, out = self.pending[nbytes:], self.pending[:nbytes]
        return out
    

class S:
    def __init__(self, delta, t_delta) -> None:
        self.delta = delta
        self.t_delta = t_delta
    
    def compute_q(self, u):
        self.q = transpose([
            bytes2bits(xor(ti, ui) if bi else ti)
            for ti, ui, bi in zip(self.t_delta, u, self.delta)
        ])

    def check(self, chi, x_, t_):
        q_ = sum([F2n(qi) * xi for qi, xi in zip(self.q, chi)])
        return q_ == t_ + x_ * F2n(self.delta)


def chall():
    prng = PRNG()
    t0 = [prng.randbytes(l_bytes) for _ in range(n)]
    t1 = [prng.randbytes(l_bytes) for _ in range(n)]
    print("t0 = ", b64encode(b"".join(t0)).decode())
    print("t1 = ", b64encode(b"".join(t1)).decode())
    ts = [t0, t1]

    delta_bytes = random.randbytes(n_bytes)
    delta = bytes2bits(delta_bytes)
    t_delta = [ts[b][i] for i, b in enumerate(delta)]

    S_ = S(delta, t_delta)

    def handler(signum, frame):
        print("Timeout")
        exit(0)
    
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(180)

    for _ in range(100):
        try:
            u = recv_bytes("u = ", n * l_bytes)
            u = [u[i: i + l_bytes] for i in range(0, len(u), l_bytes)]
            S_.compute_q(u)

            chi = [prng.randbytes(n_bytes) for _ in range(l)]
            
            print(f"chi = {b64encode(b''.join(chi)).decode()}")

            chi = [F2n(bytes2bits(xi)) for xi in chi]
            x_ = F2n(bytes2bits(recv_bytes("x_ = ", n_bytes)))    
            t_ = F2n(bytes2bits(recv_bytes("t_ = ", n_bytes)))

            if not S_.check(chi, x_, t_):
                raise Exception(":pekowide:")

            option = input(">>> ")
            if option == "1":
                guess = recv_bytes("What's my secret? ", n_bytes)
                if guess == delta_bytes:
                    flag = open("flag.txt").read()
                    print("Good job! Here's your flag: ", flag)
                else:
                    break
            elif option == "2":
                continue
            else:
                break
        except Exception as e:
            print(e)
            continue


chall()
