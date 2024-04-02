#!/usr/bin/sage
import hashlib

def solve_part1():
    SUB_TABLE = set() # contains (a, b, c) such that a - b == c (mod p)
    MUL_TABLE = set() # contains (a, b, c) such that a * b == c (mod p)
    REGISTERED_EC = set() # contains elliptic curve points in y^2 = x^3 + 7 (mod p)
    REGISTERED_X = set() # contains x-coordinates of a elliptic curve point of REGISTERED_EC

    bn254 = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    x_start = int(input()) % p 
    y_start = int(input()) % p
    assert (y_start * y_start) % p == (x_start * x_start * x_start + 7) % p 

    # this target value is the target x-coordinate
    target = int.from_bytes(hashlib.sha256(str(x_start).encode() + b"#" + str(y_start).encode()).digest(), "big") % p 

    # (x_start, y_start) is known to be a valid elliptic curve point
    REGISTERED_EC.add((x_start, y_start))
    REGISTERED_X.add(x_start)

    count = 0
    while True:
        count += 1
        assert count < 20000
        whi = int(input())
        if whi == 1 or whi == 2:
            a = int(input())
            b = int(input())
            quotient = int(input())
            result = int(input())
            assert 0 <= a < (1 << 256)
            assert 0 <= b < (1 << 256)
            assert 0 <= quotient < (1 << 256)
            assert 0 <= result < (1 << 256)
            if whi == 1:
                # add (a, b, result) in SUB_TABLE
                assert (a - b + p - quotient * p - result) % bn254 == 0 
                assert (a - b + p - quotient * p - result) % (1 << 256) == 0
                SUB_TABLE.add((a, b, result))
            if whi == 2:
                # add (a, b, result) in MUL_TABLE
                assert (a * b - quotient * p - result) % bn254 == 0 
                assert (a * b - quotient * p - result) % (1 << 256) == 0
                MUL_TABLE.add((a, b, result))
        if whi == 3:
            # check two points (x1, y1), (x2, y2) are already registered elliptic curve points
            # check (x3, y3) = (x1, y1) + (x2, y2) via elliptic curve addition
            # valid computation over (mod p) is checked by SUB_TABLE and MUL_TABLE
            x1 = int(input())
            y1 = int(input())
            x2 = int(input())
            y2 = int(input())
            assert (x1, y1) in REGISTERED_EC # check (x1, y1) is a known valid elliptic curve point
            assert (x2, y2) in REGISTERED_EC # check (x2, y2) is a known valid elliptic curve point
            lam = int(input())
            if x1 == x2 and y1 == y2: # point doubling algorithm
                x_sq = int(input())
                x_sq_3 = int(input())
                y_2 = int(input())
                y_2_inv = int(input())
                assert (x1, x1, x_sq) in MUL_TABLE # check x_sq = x1^2
                assert (x_sq, 3, x_sq_3) in MUL_TABLE # check x_sq_3 = 3 * x1^2
                assert (y1, 2, y_2) in MUL_TABLE # check y_2 = 2 * y1
                assert (y_2, y_2_inv, 1) in MUL_TABLE # check y_2_inv = 1 / (2 * y1)
                assert (x_sq_3, y_2_inv, lam) in MUL_TABLE # check lam = (3 * x1^2) / (2 * y1)
            else:
                y_diff = int(input())
                x_diff = int(input())
                x_diff_inv = int(input())
                assert (y2, y1, y_diff) in SUB_TABLE # check y_diff = y2 - y1
                assert (x2, x1, x_diff) in SUB_TABLE # check x_diff = x2 - x1
                assert (x_diff, x_diff_inv, 1) in MUL_TABLE # check x_diff_inv = 1 / (x2 - x1)
                assert (y_diff, x_diff_inv, lam) in MUL_TABLE # check lam = (y2 - y1) / (x2 - x1)
            lam_sq = int(input())
            lam_sq_minus_x1 = int(input())
            x_final = int(input())
            x1_minus_x_final = int(input())
            lam_mul_x1_minus_x_final = int(input())
            y_final = int(input())
            assert (lam, lam, lam_sq) in MUL_TABLE # check lam_sq = lam^2
            assert (lam_sq, x1, lam_sq_minus_x1) in SUB_TABLE # check lam_sq_minus_x1 = lam^2 - x1
            assert (lam_sq_minus_x1, x2, x_final) in SUB_TABLE # check x_final = lam^2 - x1 - x2
            assert (x1, x_final, x1_minus_x_final) in SUB_TABLE # check x1_minus_x_final = x1 - x_final
            assert (lam, x1_minus_x_final, lam_mul_x1_minus_x_final) in MUL_TABLE  # check lam_mul_x1_minus_x_final = lam * (x1 - x_final)
            assert (lam_mul_x1_minus_x_final, y1, y_final) in SUB_TABLE # check y_final = lam * (x1 - x_final) - y1
            REGISTERED_EC.add((x_final, y_final)) # add (x_final, y_final) to REGISTERED_EC
            REGISTERED_X.add(x_final) # add x_final to REGISTERED_X
        if whi == 4:
            break 

    assert target in REGISTERED_X # end with the target x-coordinate in REGISTERED_X

def solve_part2():
    ADD_TABLE = set() # contains (a, b, c) such that a + b == c (mod p)
    MUL_TABLE = set() # contains (a, b, c) such that a * b == c (mod p)
    
    # Curve25519
    p = (1 << 255) - 19 
    E = EllipticCurve(GF(p), [0, 486662, 0, 1, 0])
    G = E(GF(p)(9), GF(p)(43114425171068552920764898935933967039370386198203806730763910166200978582548))
    
    # Commit a set of NUM_POINTS points in Curve25519
    NUM_POINTS = 165
    commit = bytes.fromhex(input().strip())
    assert len(commit) == 32 * NUM_POINTS 

    # this is the target point on Curve25519
    target = int.from_bytes(hashlib.sha256(commit).digest(), "big") * G

    # Add tuples to ADD_TABLE and MUL_TABLE by submitting proofs
    count = 0
    while True:
        count += 1
        assert count < 20000
        whi = int(input())
        if whi == 1 or whi == 2:
            a = int(input())
            b = int(input())
            quotient = int(input())
            result = int(input())
            assert 0 <= a < (1 << 256)
            assert 0 <= b < (1 << 256)
            assert 0 <= quotient < (1 << 256)
            assert 0 <= result < (1 << 256)
            if whi == 1:
                assert (a + b - (quotient * p + result)) % (1 << 512) == 0
                ADD_TABLE.add((a, b, result))
            if whi == 2:
                assert (a * b - (quotient * p + result)) % (1 << 512) == 0
                MUL_TABLE.add((a, b, result))
        if whi == 3:
            break
    
    # submit a bitmask corresponding to a subset
    # the subset sum of the points you committed before must equal to the target point
    bmask = int(input())
    assert 0 <= bmask < (1 << NUM_POINTS)
    
    tot = 0 * G

    for i in range(NUM_POINTS):
        if ((bmask >> i) & 1) == 0: # the bitmask doesn't contain the i'th point, so skip
            continue 
        # the bitmask contains the i'th point
        # decompress the 32 bytes, with proof, to obtain a point on Curve25519
        x = int(input())
        y = int(input())
        top_value = int(input()) 
        x_sq = int(input())
        x_cube = int(input())
        x_sq_486662 = int(input())
        sum1 = int(input())
        sum2 = int(input())
        # x_sum is the x-coordinate encoded in the 32 byte compressed format
        x_sum = 0
        for j in range(32):
            x_sum += commit[i * 32 + j] * (256 ** j)
        x_sum &= ((1 << 255) - 1)
        # bit is the parity of the y-coordinate encoded in the 32 byte compressed format
        bit = (commit[i * 32 + 31] >> 7) & 1
        assert x == x_sum # check x matches the encoded x-coordinate
        assert 0 <= top_value < (1 << 255) 
        assert y == top_value * 2 + bit # check bit matches the parity of y
        assert (x, x, x_sq) in MUL_TABLE # check x_sq = x^2
        assert (x, x_sq, x_cube) in MUL_TABLE # check x_cube = x^3
        assert (x_sq, 486662, x_sq_486662) in MUL_TABLE # check x_sq_486662 = 486662 * x^2
        assert (x_cube, x_sq_486662, sum1) in ADD_TABLE # check sum1 = x^3 + 486662 * x^2
        assert (sum1, x, sum2) in ADD_TABLE # check sum2 = x^3 + 486662 * x^2 + x 
        assert (y, y, sum2) in MUL_TABLE # check y^2 = x^3 + 486662 * x^2 + x, so (x, y) is in Curve25519
        recovered_point = E(GF(p)(x), GF(p)(y)) 
        tot += recovered_point # add the recovered point to the subset sum
    
    assert tot == target # assert the subset sum matches the target point

solve_part1()
print("PART 1 SOLVED!")

solve_part2()
print("PART 2 SOLVED!")

flag = open("flag.txt", "r").read()
print(flag)