import marshal
from opcode import opmap
from types import CodeType
import sys
import random

b = open('run.pyc', 'wb')

# https://github.com/python/cpython/blob/v3.10.0/Lib/importlib/_bootstrap_external.py
MAGIC = (3439).to_bytes(2, 'little') + b'\x0d\x0a'
b.write(MAGIC)
b.write(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


def _(op, n):
    if n // 256 != 0:
        return [opmap['EXTENDED_ARG'], n // 256, opmap[op], n % 256]
    else:
        return [opmap[op], n]


FLAG = b'ACSC{d1d_u_notice_the_oob_L04D_C0N5T?}'


def num(n):
    if n == 0:
        return [opmap["MATCH_MAPPING"], 0]
    one = [opmap["BUILD_TUPLE"], 0, opmap["MATCH_SEQUENCE"], 0] + [opmap['ROT_TWO'], 0, opmap['POP_TOP'], 0]
    if n == 1:
        return one
    half = num(n // 2)
    ret = half + [opmap["DUP_TOP"], 0, opmap["BINARY_ADD"], 0]
    if n % 2 == 1:
        ret += one + [opmap["BINARY_ADD"], 0]
    
    # # Obfuscation: add random jumps
    # if random.random() < 0.1:
    #     n = random.randint(0, 10)
    #     ret += [opmap['JUMP_FORWARD'], n]
    #     for _ in range(n):
    #         ret += [random.randint(0, 255), random.randint(0, 255)]
    return ret


code = [
    opmap['LOAD_NAME'], 1,
        opmap['LOAD_CONST'], 0,
    opmap['CALL_FUNCTION'], 1,

    opmap['LOAD_CONST'], 12, # str
        opmap['LOAD_CONST'], 20, # bytes
            *sum(map(num, FLAG), []),
            opmap['BUILD_TUPLE'], len(FLAG),
        opmap['CALL_FUNCTION'], 1,
    opmap['CALL_FUNCTION'], 1,

    *num(2),
    *num(1), opmap['UNARY_NEGATIVE'], 0, # -1
    opmap['BUILD_SLICE'], 2,
    opmap['BINARY_SUBSCR'], 0,

    opmap['COMPARE_OP'], 2,  # ==
    opmap['POP_JUMP_IF_FALSE'], 0,

    opmap['LOAD_NAME'], 1, # print("CORRECT")
        opmap['LOAD_CONST'], 1,
    opmap['CALL_FUNCTION'], 1,

    opmap['RETURN_VALUE'], 0,
]


c = CodeType(
    0, 0, 0, 0, 0, 0,
    bytes(code),
    ('FLAG> ', 'CORRECT',),
    ('print', 'input'),
    (), '<sandbox>', '<eval>', 0, b'', ()
)

b.write(marshal.dumps(c))
b.close()
