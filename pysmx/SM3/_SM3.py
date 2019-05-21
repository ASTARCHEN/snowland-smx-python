#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: _SM3.py
# @time: 2018/12/03 15:26
# @Software: PyCharm


from math import ceil
import numpy as np
from functools import reduce
from copy import deepcopy, copy
import struct
from numba import jit

npa = np.array

BIT_BLOCK_H = npa([0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF])
BIT_BLOCK_L = npa([0x0, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF])
BIT_EACH = npa([1, 2, 4, 8, 16, 32, 64, 128, 256])
BIT_EACH_32 = npa([1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144,
                   524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456,
                   536870912, 1073741824, 2147483648, 4294967296])
IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
IV = int(IV.replace(" ", ""), 16)
IV = npa([(IV >> ((7 - i) * 32)) & 0xffffffff for i in range(8)], dtype=np.uint32)


def rotate_left(a, k):
    k %= 32
    high, low = np.divmod(a, BIT_EACH_32[32 - k])
    return high + low * BIT_EACH_32[k]


T_j = npa([0x79cc4519] * 16 + [0x7a879d8a] * 48)
T_j_rotate_left = [rotate_left(Tj, j) for j, Tj in enumerate(T_j)]


def FF_j(X, Y, Z, j):
    # 已经融合到内部了
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG_j(X, Y, Z, j):
    # 已经融合在内部了
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | ((~ X) & Z)


def P_0(X):
    high, low = np.divmod(X, BIT_EACH_32[23])
    r_l_9 = high + low * BIT_EACH_32[9]
    high, low = np.divmod(X, BIT_EACH_32[15])
    r_l_17 = high + low * BIT_EACH_32[17]
    # return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))
    return X ^ r_l_9 ^ r_l_17


def P_1(X):
    high, low = np.divmod(X, BIT_EACH_32[17])
    r_l_15 = high + low * BIT_EACH_32[15]
    high, low = np.divmod(X, BIT_EACH_32[9])
    r_l_23 = high + low * BIT_EACH_32[23]
    return X ^ r_l_15 ^ r_l_23


def PUT_UINT32_BE(n):
    return [int((n >> 24) & 0xff), int((n >> 16) & 0xff), int((n >> 8) & 0xff), int(n & 0xff)]


def __cf_reduce_16_64(V_i, j, W=None):
    high_A12, low_A12 = np.divmod(V_i[0], BIT_EACH_32[20])
    r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
    high, low = np.divmod((r_l_12 + V_i[4] + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
    SS1 = high + low * BIT_EACH_32[7]
    SS2 = SS1 ^ r_l_12
    # FF
    TT1 = (((V_i[0] & V_i[1]) | (V_i[0] & V_i[2]) | (V_i[1] & V_i[2])) + V_i[3] + SS2 + (W[j] ^ W[j + 4])) & 0xffffffff
    # GG
    TT2 = (((V_i[4] & V_i[5]) | ((~ V_i[4]) & V_i[6])) + V_i[7] + SS1 + W[j]) & 0xffffffff
    high_B9, low_B9 = np.divmod(V_i[1], BIT_EACH_32[23])
    high_F19, low_F19 = np.divmod(V_i[5], BIT_EACH_32[13])
    return [TT1, V_i[0], high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, V_i[2], P_0(TT2) & 0xffffffff, \
            V_i[4], high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, V_i[6]]


def __cf_reduce_0_16(V_i, j, W=None):
    high_A12, low_A12 = np.divmod(V_i[0], BIT_EACH_32[20])
    r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
    high, low = np.divmod((r_l_12 + V_i[4] + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
    SS1 = high + low * BIT_EACH_32[7]
    SS2 = SS1 ^ r_l_12
    # FF
    TT1 = ((V_i[0] ^ V_i[1] ^ V_i[2]) + V_i[3] + SS2 + (W[j] ^ W[j + 4])) & 0xffffffff
    # GG
    TT2 = ((V_i[4] ^ V_i[5] ^ V_i[6]) + V_i[7] + SS1 + W[j]) & 0xffffffff
    high_B9, low_B9 = np.divmod(V_i[1], BIT_EACH_32[23])
    high_F19, low_F19 = np.divmod(V_i[5], BIT_EACH_32[13])
    high, low = np.divmod(TT2, BIT_EACH_32[23])
    r_l_9 = high + low * BIT_EACH_32[9]
    high, low = np.divmod(TT2, BIT_EACH_32[15])
    r_l_17 = high + low * BIT_EACH_32[17]
    return [TT1, V_i[0], high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, V_i[2], (TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, \
            V_i[4], high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, V_i[6]]


def CF(V_i, B_i):
    weight = BIT_EACH_32[24::-8]
    B_i = B_i.reshape((len(B_i) // 4, 4))
    W = np.append(B_i.dot(weight), np.zeros(52, dtype=np.int64))
    for j in np.arange(16, 68):
        high_W3_15, low_W3_15 = np.divmod(W[j - 3], BIT_EACH_32[17])
        high_W13_7, low_W13_7 = np.divmod(W[j - 13], BIT_EACH_32[25])
        # P_1
        X = W[j - 16] ^ W[j - 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])
        high_P1_15, low_P1_15 = np.divmod(X, BIT_EACH_32[17])
        r_l_15 = high_P1_15 + low_P1_15 * BIT_EACH_32[15]
        high_P1_23, low_P1_23 = np.divmod(X, BIT_EACH_32[9])
        r_l_23 = high_P1_23 + low_P1_23 * BIT_EACH_32[23]
        W[j] = (X ^ r_l_15 ^ r_l_23 ^ (high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[j - 6])

    W_1 = W[:-4] ^ W[4:]
    A, B, C, D, E, F, G, H = V_i
    for j in np.arange(0, 16):
        high_A12, low_A12 = np.divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = np.divmod((r_l_12 + E + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        # FF
        TT1 = ((A ^ B ^ C) + D + SS2 + W_1[j]) & 0xffffffff
        # GG
        TT2 = ((E ^ F ^ G) + H + SS1 + W[j]) & 0xffffffff
        high_B9, low_B9 = np.divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = np.divmod(F, BIT_EACH_32[13])
        high, low = np.divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = np.divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    for j in np.arange(16, 64):
        high_A12, low_A12 = np.divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = np.divmod((r_l_12 + E + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        # FF
        TT1 = (((A & B) | (A & C) | (B & C)) + D + SS2 + W_1[j]) & 0xffffffff
        # GG
        TT2 = (((E & F) | ((~ E) & G)) + H + SS1 + W[j]) & 0xffffffff
        high_B9, low_B9 = np.divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = np.divmod(F, BIT_EACH_32[13])
        high, low = np.divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = np.divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    return npa((A, B, C, D, E, F, G, H)) ^ V_i


def CF_7(V_i, B_i):
    weight = BIT_EACH_32[24::-8]
    B_i = B_i.reshape((len(B_i) // 4, 4))
    W = B_i.dot(weight)
    for j in np.arange(16, 68):
        high_W3_15, low_W3_15 = np.divmod(W[-3], BIT_EACH_32[17])
        high_W13_7, low_W13_7 = np.divmod(W[-13], BIT_EACH_32[25])
        # P_1
        X = W[- 16] ^ W[- 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])
        high_P1_15, low_P1_15 = np.divmod(X, BIT_EACH_32[17])
        r_l_15 = high_P1_15 + low_P1_15 * BIT_EACH_32[15]
        high_P1_23, low_P1_23 = np.divmod(X, BIT_EACH_32[9])
        r_l_23 = high_P1_23 + low_P1_23 * BIT_EACH_32[23]
        # return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))
        W = np.append(W, X ^ r_l_15 ^ r_l_23 ^ (high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])
        # W.append(X ^ r_l_15 ^ r_l_23 ^ (high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])

        # W.append(P_1(W[- 16] ^ W[- 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])) ^ (
        #         high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])
    W_1 = W[:-4] ^ W[4:]
    A, B, C, D, E, F, G, H = V_i
    for j in np.arange(0, 16):
        high_A12, low_A12 = np.divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = np.divmod((r_l_12 + E + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        # Wj = (B_i[ind] * BIT_EACH_32[24]) + (B_i[ind + 1] * BIT_EACH_32[16]) + (B_i[ind + 2] * BIT_EACH_32[8]) + (B_i[ind + 3])
        # FF
        TT1 = ((A ^ B ^ C) + D + SS2 + W_1[j]) & 0xffffffff
        # GG
        TT2 = ((E ^ F ^ G) + H + SS1 + W[j]) & 0xffffffff
        high_B9, low_B9 = np.divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = np.divmod(F, BIT_EACH_32[13])
        high, low = np.divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = np.divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    for j in np.arange(16, 64):
        high_A12, low_A12 = np.divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = np.divmod((r_l_12 + E + T_j_rotate_left[j]) & 0xffffffff, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        # FF
        TT1 = (((A & B) | (A & C) | (B & C)) + D + SS2 + W_1[j]) & 0xffffffff
        # GG
        TT2 = (((E & F) | ((~ E) & G)) + H + SS1 + W[j]) & 0xffffffff
        high_B9, low_B9 = np.divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = np.divmod(F, BIT_EACH_32[13])
        high, low = np.divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = np.divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    return npa((A, B, C, D, E, F, G, H)) ^ V_i


def CF2(V_i, B_i):
    W = [(B_i[ind] * BIT_EACH_32[24]) + (B_i[ind + 1] * BIT_EACH_32[16]) + (B_i[ind + 2] * BIT_EACH_32[8]) + (
        B_i[ind + 3]) for ind in range(0, 64, 4)]
    for j in range(16, 68):
        high_W3_15, low_W3_15 = np.divmod(W[-3], BIT_EACH_32[17])
        high_W13_7, low_W13_7 = np.divmod(W[-13], BIT_EACH_32[25])
        W.append(P_1(W[- 16] ^ W[- 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])) ^ (
                high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])
    V_i_1 = reduce(lambda a, b: __cf_reduce_0_16(a, b, W), range(0, 16), V_i.copy())
    V_i_2 = reduce(lambda a, b: __cf_reduce_16_64(a, b, W), range(16, 64), V_i_1)
    return [V_i_2[0] ^ V_i[0], V_i_2[1] ^ V_i[1], V_i_2[2] ^ V_i[2],
            V_i_2[3] ^ V_i[3], V_i_2[4] ^ V_i[4], V_i_2[5] ^ V_i[5], V_i_2[6] ^ V_i[6], V_i_2[7] ^ V_i[7]]


def CF3(V_i, B_i):
    W = [(B_i[ind] * BIT_EACH_32[24]) + (B_i[ind + 1] * BIT_EACH_32[16]) + (B_i[ind + 2] * BIT_EACH_32[8]) + (
        B_i[ind + 3]) for ind in range(0, 64, 4)]
    for j in range(16, 68):
        # a = (P_1(W[- 16] ^ W[- 9] ^ (rotate_left(W[- 3], 15))) ^ (rotate_left(W[- 13], 7)) ^ W[- 6])
        high_W3_15, low_W3_15 = np.divmod(W[-3], BIT_EACH_32[17])
        high_W13_7, low_W13_7 = np.divmod(W[-13], BIT_EACH_32[25])
        W.append(P_1(W[- 16] ^ W[- 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])) ^ (
                high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])
    V_i_1 = reduce(lambda a, b: __cf_reduce_0_16(a, b, W), range(0, 16), V_i.copy())
    V_i_2 = reduce(lambda a, b: __cf_reduce_16_64(a, b, W), range(16, 64), V_i_1)
    return [V_i_2[0] ^ V_i[0], V_i_2[1] ^ V_i[1], V_i_2[2] ^ V_i[2],
            V_i_2[3] ^ V_i[3], V_i_2[4] ^ V_i[4], V_i_2[5] ^ V_i[5], V_i_2[6] ^ V_i[6], V_i_2[7] ^ V_i[7]]


def digest(msg, Hexstr=0):
    if isinstance(msg, list):
        pass
    else:
        msg = hex2byte(msg) if Hexstr else str2bytes(msg)
    len1 = len(msg)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    bit_length = len1 * 8
    msg = np.hstack((msg, 0x80, np.zeros(range_end - reserve1, dtype=np.uint8), list(struct.pack(">Q", bit_length))))
    # B = (msg[i:i + 64] for i in range(0, len(msg), 64))
    B = msg.reshape((len(msg) // 64, 64))
    y = reduce(CF, B, IV)
    b = bytearray()
    [b.extend(PUT_UINT32_BE(each)) for each in y]
    return bytes(b)


def hash_msg(msg):
    return digest(msg, 0).hex()


def str2bytes(msg: str, encoding='utf-8'):
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
    return msg.decode(decode) if isinstance(msg, (bytes, bytearray)) else msg


def hex2byte(msg):
    """
    16进制字符串转换成byte列表
    :param msg:
    :return:
    """
    if not isinstance(msg, str):
        raise ValueError('message must be string')
    ml = len(msg)
    if (ml & 1) != 0:
        msg = '0' + msg
    return list(bytes.fromhex(msg))


def Hash_sm3(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return hash_msg(msg_byte)


hexdigest = Hash_sm3


def _BKDF(Z, klen: int):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    klen = int(klen)
    rcnt = int(np.ceil(klen / 32))
    Zin = hex2byte(Z)
    b = bytearray()
    [b.extend(digest(Zin + PUT_UINT32_BE(ct), 0)) for ct in range(1, rcnt + 1)]
    return b[:klen]


def KDF(Z, klen: int):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    return _BKDF(Z, klen).hex()


class SM3Type(object):
    name = 'SM3'
    digest_size = 32
    block_size = 64

    def __init__(self, msg=b'', encoding='utf-8'):
        self.encoding = encoding
        self.msg = bytearray(str2bytes(msg, self.encoding))

    def update(self, msg):
        self.msg.extend(str2bytes(msg, self.encoding))

    def digest(self):
        return digest(self.msg, 0)

    def hexdigest(self):
        return hexdigest(self.msg, 0)

    def copy(self):
        return copy(self)


SM3 = SM3Type

del CF2
del CF3
