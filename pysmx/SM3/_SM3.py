import numpy as np
from functools import reduce
from copy import deepcopy, copy

npa = np.array

BIT_BLOCK_H = npa([0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF])
BIT_BLOCK_L = npa([0x0, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF])
BIT_EACH = npa([1, 2, 4, 8, 16, 32, 64, 128, 256])

IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
IV = int(IV.replace(" ", ""), 16)
IV = [(IV >> ((7 - i) * 32)) & 0xFFFFFFFF for i in range(8)]


def rotate_left(a, k):
    k %= 32
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))


T_j = npa([0x79cc4519] * 16 + [0x7a879d8a] * 48)


def FF_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | ((~ X) & Z)


def P_0(X):
    return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))


def P_1(X):
    return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))


def CF(V_i, B_i):
    W = np.empty(68, dtype=np.int64)
    W[:16] = npa(
        [(B_i[ind] << 24) + (B_i[ind + 1] << 16) + (B_i[ind + 2] << 8) + (B_i[ind + 3]) for ind in range(0, 64, 4)])
    for j in range(16, 68):
        W[j] = (P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6])
    W_1 = W[:64] ^ W[4:]
    A, B, C, D, E, F, G, H = V_i
    for j in range(0, 64):
        SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ (rotate_left(A, 12))
        TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D, E, F, G, H = TT1, A, rotate_left(B, 9) & 0xffffffff, C, P_0(
            TT2) & 0xffffffff, E, rotate_left(F, 19) & 0xffffffff, G
    return npa([A, B, C, D, E, F, G, H]) ^ V_i


def hash_msg(msg):
    # print(msg)
    msg = npa(list(msg))
    len1 = len(msg)
    msg = np.append(msg, 0x80)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    msg = np.append(msg, [0] * (range_end - reserve1))
    bit_length = len1 * 8
    bit_length_str = []
    for i in range(8):
        bit_length, t = divmod(bit_length, 0x100)
        bit_length_str.insert(0, t)
    msg = np.append(msg, bit_length_str)
    # print(msg)
    B = msg.reshape((len(msg) // 64, 64))
    y = reduce(CF, B, IV)
    return "".join(['%08x' % i for i in y])


def str2bytes(msg, encoding='utf-8'):
    """
    字符串转换成byte数组
    :param msg: 信息串
    :param encoding: 编码
    :return:
    """
    msg_bytearray = msg.encode(encoding) if isinstance(msg, str) else msg
    return list(msg_bytearray)


def byte2str(msg, decode='utf-8'):
    """
    byte数组转字符串
    :param msg:
    :param decode:
    :return:
    """
    str1 = bytes(msg)
    return str1.decode(decode)


def hex2byte(msg):
    """
    16进制字符串转换成byte列表
    :param msg:
    :return:
    """
    ml = len(msg)
    if ml % 2 != 0:
        msg = '0' + msg
    return bytes.fromhex(msg)


def byte2hex(msg):  # byte数组转换成16进制字符串
    return "".join(['%02x' % each for each in msg])


def Hash_sm3(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return hash_msg(msg_byte)


hexdigest = Hash_sm3


def digest(msg, Hexstr=0, encoding='utf-8'):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return bytes(hash_msg(msg_byte), encoding)


def KDF(Z, klen):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    klen = int(klen)
    rcnt = int(np.ceil(klen / 32))
    Zin = hex2byte(Z)
    Ha = "".join([hash_msg(Zin + hex2byte('%08x' % ct)) for ct in range(1, rcnt + 1)])
    return Ha[0: klen * 2]


class SM3Type(object):
    name = 'SM3'
    digest_size = 64
    block_size = 64

    def __init__(self, msg=b'', encoding='utf-8'):
        self.encoding = encoding
        self.msg = str2bytes(msg, self.encoding)

    def update(self, msg):
        self.msg += str2bytes(msg, self.encoding)

    def digest(self):
        return digest(self.msg, 0)

    def hexdigest(self):
        return hexdigest(self.msg, 0)

    def copy(self):
        return deepcopy(self)


SM3 = SM3Type
