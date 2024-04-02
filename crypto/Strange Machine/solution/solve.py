from sage.all import *
from pwn import * 

conn = process("sage ../challenge/task.sage", shell = True)

def solve1():
    bn254 = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = 76531530484971518452639906442761194412664870345624485669037534195749499544671
    y = 55794286580076521502037307821879535877242241109554041978900563137772364196793

    def mult(a, b, c):
        conn.sendline(b"2")
        quotient = ((a * b - c) * inverse_mod(p, bn254 << 256)) % (bn254 << 256)
        for v in [a, b, quotient, c]:
            conn.sendline(str(v).encode())
    
    def sub(a, b, c):
        conn.sendline(b"1")
        quotient = ((a - b + p - c) * inverse_mod(p, bn254 << 256)) % (bn254 << 256)
        for v in [a, b, quotient, c]:
            conn.sendline(str(v).encode())

    def double_ec(x, y, xsq):
        x_sq_3 = (3 * xsq) % p 
        y_2 = (2 * y) % p 
        y_2_inv = (inverse_mod(y_2, p)) % p
        lam = (x_sq_3 * y_2_inv) % p 
        lam_sq = (lam * lam) % p 
        lam_sq_minus_x1 = (lam_sq - x + p) % p 
        x_final = (lam_sq_minus_x1 - x + p) % p
        x_1_minus_x_final = (x - x_final + p) % p 
        lam_mul_x_1_minus_x_final = (lam * x_1_minus_x_final) % p 
        y_final = (lam_mul_x_1_minus_x_final - y + p) % p

        mult(x, x, xsq)
        mult(xsq, 3, x_sq_3)
        mult(y, 2, y_2)
        mult(y_2, y_2_inv, 1)
        mult(x_sq_3, y_2_inv, lam)
        mult(lam, lam, lam_sq)
        sub(lam_sq, x, lam_sq_minus_x1)
        sub(lam_sq_minus_x1, x, x_final)
        sub(x, x_final, x_1_minus_x_final)
        mult(lam, x_1_minus_x_final, lam_mul_x_1_minus_x_final)
        sub(lam_mul_x_1_minus_x_final, y, y_final)

        conn.sendline(b"3")
        for v in [x, y, x, y, lam, xsq, x_sq_3, y_2, y_2_inv, lam_sq, lam_sq_minus_x1, x_final, x_1_minus_x_final, lam_mul_x_1_minus_x_final, y_final]:
            conn.sendline(str(v).encode())
        
        return (x_final, y_final)

    def add_ec(point1, point2):
        x1, y1 = point1 
        x2, y2 = point2

        y_diff = (y2 - y1 + p) % p 
        x_diff = (x2 - x1 + p) % p 
        x_diff_inv = int(inverse_mod(x_diff, p)) % p 
        lam = (y_diff * x_diff_inv) % p
        lam_sq = (lam * lam) % p 
        lam_sq_minus_x1 = (lam_sq - x1 + p) % p 
        x_final = (lam_sq_minus_x1 - x2 + p) % p
        x_1_minus_x_final = (x1 - x_final + p) % p 
        lam_mul_x_1_minus_x_final = (lam * x_1_minus_x_final) % p 
        y_final = (lam_mul_x_1_minus_x_final - y1 + p) % p

        sub(y2, y1, y_diff)
        sub(x2, x1, x_diff)
        mult(x_diff, x_diff_inv, 1)
        mult(y_diff, x_diff_inv, lam)
        mult(lam, lam, lam_sq)
        sub(lam_sq, x1, lam_sq_minus_x1)
        sub(lam_sq_minus_x1, x2, x_final)
        sub(x1, x_final, x_1_minus_x_final)
        mult(lam, x_1_minus_x_final, lam_mul_x_1_minus_x_final)
        sub(lam_mul_x_1_minus_x_final, y1, y_final)

        conn.sendline(b"3")
        for v in [x1, y1, x2, y2, lam, y_diff, x_diff, x_diff_inv, lam_sq, lam_sq_minus_x1, x_final, x_1_minus_x_final, lam_mul_x_1_minus_x_final, y_final]:
            conn.sendline(str(v).encode())
        
        return (x_final, y_final)

    conn.sendline(str(x).encode())
    conn.sendline(str(y).encode())

    target = int.from_bytes(hashlib.sha256(str(x).encode() + b"#" + str(y).encode()).digest(), "big") % p 
    target_x = target
    target_y = GF(p)(target ** 3).square_root()

    delta = 14477608212821005808688817108937565514616830304980834051587809202023487341045

    xsq = (x * x + delta) % p 
    x_ret, y_ret = double_ec(x, y, xsq)

    start = (x_ret * inverse_mod(y_ret, p)) % p 
    final = (target_x * inverse_mod(int(target_y), p)) % p

    nlog = int((final * inverse_mod(start, p)) % p)

    pp = [(x_ret, y_ret)] 
    for i in range(1, 256):
        pp.append(double_ec(pp[i-1][0], pp[i-1][1], (pp[i-1][0] ** 2) % p))
    
    bits = []
    for i in range(256):
        if ((nlog >> i) & 1) == 1:
            bits.append(i)

    assert len(bits) >= 2
    x_cur, y_cur = add_ec(pp[bits[0]], pp[bits[1]])
    for i in range(2, len(bits)):
        x_cur, y_cur = add_ec((x_cur, y_cur), pp[bits[i]])
    
    conn.sendline(b"4")
    print(conn.recvline())
    

def solve2():
    p = (1 << 255) - 19 
    E = EllipticCurve(GF(p), [0,486662,0,1,0])
    G = E(GF(p)(9), GF(p)(43114425171068552920764898935933967039370386198203806730763910166200978582548))
    N = (1 << 252) + 27742317777372353535851937790883648493

    cut = 3 * p // 5 
    
    def mult(a, b, c):
        conn.sendline(b"2")
        quotient = (a * b - c) // p
        for v in [a, b, quotient, c]:
            conn.sendline(str(v).encode())
    
    def add(a, b, c):
        conn.sendline(b"1")
        quotient = (a + b - c) // p
        for v in [a, b, quotient, c]:
            conn.sendline(str(v).encode())

    res = []
    for i in range(165):
        for j in range(20):
            if j % 3 == 0:
                continue 
            tt = (3 ** i) * j * G
            if int(tt.xy()[1]) >= cut:
                res.append((tt, j))
                break 

    fin_bytes = []
    for i in range(165):
        x = int(res[i][0].xy()[0])
        for j in range(32):
            fin_bytes.append((x >> (8 * j)) & 255)
        y = int(res[i][0].xy()[1]) % 2 
        fin_bytes[32 * i + 31] |= (y * 128)

    sent_bytes = bytes(fin_bytes)
    target = int.from_bytes(hashlib.sha256(sent_bytes).digest(), "big") % N

    bmask = 0
    mode = []
    for i in range(165):
        v = res[i][1]
        if v % 3 == target % 3:
            target = (target - v) // 3 
            bmask += (1 << i)
            mode.append(1)
        else:
            if (v + target) % 3 == 0:
                target = (target + v) // 3 
                bmask += (1 << i)
                mode.append(-1)
            else:
                target = target // 3 
                mode.append(0)
    
    assert target == 0
    conn.sendline(sent_bytes.hex().encode())

    data = []
    for i in range(165):
        if mode[i] == 0:
            data.append([])
            continue 
        x = int(res[i][0].xy()[0])
        y = int(res[i][0].xy()[1])
        if mode[i] == -1:
            y = 2 * p - y
        top_value = y // 2
        x_sq = (x * x) % p
        x_cube = (x ** 3) % p 
        x_sq_486662 = (x_sq * 486662) % p
        sum1 = (x_cube + x_sq_486662) % p 
        sum2 = (sum1 + x) % p
        data.append([x, y, top_value, x_sq, x_cube, x_sq_486662, sum1, sum2])

        mult(x, x, x_sq)
        mult(x, x_sq, x_cube)
        mult(x_sq, 486662, x_sq_486662)
        add(x_cube, x_sq_486662, sum1)
        add(sum1, x, sum2)
        mult(y, y, sum2)
    
    conn.sendline(b"3")
    conn.sendline(str(bmask).encode())

    for i in range(165):
        if mode[i] == 0:
            continue 
        for v in data[i]:
            conn.sendline(str(v).encode())
    
    print(conn.recvline())

solve1()
solve2()

print(conn.recvline())