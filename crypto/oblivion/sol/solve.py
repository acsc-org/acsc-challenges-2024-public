from pwn import *
from sage.all import GF
import random
from base64 import b64encode, b64decode

n = 64
n_bytes = n // 8
l = 128
l_bytes = l // 8
F2n = GF(2**n, 'ε')

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def bytes2bits(b):
    return list(map(int, "".join([format(x, "08b") for x in b])))

def bits2bytes(b, nbytes):
    b = b + [0] * (8 * nbytes - len(b))
    return bytes([int("".join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8)])

def transpose(M):
    T = [[0] * len(M) for _ in range(len(M[0]))]
    for i in range(len(M)):
        for j in range(len(M[0])):
            T[j][i] = M[i][j]
    return T

def recv_bytes(conn):
    return b64decode(conn.recvline().decode().split(" = ")[1])

'''
The protocol is an over-simplified version of https://eprint.iacr.org/2015/546.pdf
The `check` function of S corresponds to the correlation check in Fig. 7.
Intended solution is to extract delta bit-by-bit based on the output of the
correlation check.
'''
def main():
    #proc = process('./chall.sage')
    proc = remote("oblivion.chal.2024.ctf.acsc.asia", 1234)

    t0 = recv_bytes(proc)
    t0 = [t0[i: i+l_bytes] for i in range(0, len(t0), l_bytes)]

    t1 = recv_bytes(proc)
    t1 = [t1[i: i+l_bytes] for i in range(0, len(t1), l_bytes)]

    delta_bits = []

    for i in range(n + 1):
        print(i)
        xi = b"\x00" * l_bytes
        u = [xor(t0i, t1i) for t0i, t1i in zip(t0, t1)]

        if i < n:
            # corrupt q_1
            xi_prime = b"\x80" + b"\x00" * (l_bytes - 1)
            u[i] = xor(u[i], xi_prime)

        u_to_send = b64encode(b"".join(u))

        proc.sendlineafter(b"u = ", u_to_send)
        chi = recv_bytes(proc)
        chi = [F2n(bytes2bits(chi[i:i+n_bytes])) for i in range(0, len(chi), n_bytes)]

        t0T = transpose([bytes2bits(t0i) for t0i in t0])
        t0T = [F2n(t0Ti) for t0Ti in t0T]
        x_ = sum([bi * xi for bi, xi in zip(bytes2bits(xi), chi)])
        t_ = sum([t0Ti * xi for t0Ti, xi in zip(t0T, chi)])

        x_to_send = b64encode(bits2bytes(x_.polynomial().coefficients(sparse=False), n_bytes))
        t_to_send = b64encode(bits2bytes(t_.polynomial().coefficients(sparse=False), n_bytes))

        proc.sendlineafter(b"x_ = ", x_to_send)
        proc.sendlineafter(b"t_ = ", t_to_send)

        if i < n:
            if proc.recv(4) == b">>> ":
                delta_bits.append(0)
                proc.sendline(b"2")
            else:
                delta_bits.append(1)
        else:
            delta = bits2bytes(delta_bits, n_bytes)
            log.info(f"Recovered delta: {delta.hex()}")
            proc.sendlineafter(b">>> ", b"1")
            proc.sendlineafter(b"What's my secret? ", b64encode(delta))
            log.info(proc.recvline().decode())

    proc.close()


main()
