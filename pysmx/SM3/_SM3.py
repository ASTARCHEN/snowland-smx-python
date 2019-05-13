#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: _SM3.py
# @time: 2018/12/03 15:26
# @Software: PyCharm


from math import ceil
from functools import reduce
from copy import deepcopy, copy
import struct

BIT_BLOCK_H = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF]
BIT_BLOCK_L = [0x0, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
BIT_EACH = [1, 2, 4, 8, 16, 32, 64, 128, 256]
BIT_EACH_32 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144,
               524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456,
               536870912, 1073741824, 2147483648, 4294967296]
IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
IV = int(IV.replace(" ", ""), 16)
IV = [(IV >> ((7 - i) * 32)) & 0xFFFFFFFF for i in range(8)]


def rotate_left(a, k):
    k %= 32
    high, low = divmod(a, BIT_EACH_32[32 - k])
    return high + low * BIT_EACH_32[k]


T_j = [0x79cc4519] * 16 + [0x7a879d8a] * 48


def FF_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | ((~ X) & Z)


def P_0(X):
    return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))


def P_1(X):
    return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))


def CF(V_i, B_i):
    W = [(B_i[ind] * BIT_EACH_32[24]) + (B_i[ind + 1] * BIT_EACH_32[16]) + (B_i[ind + 2] * BIT_EACH_32[8]) + (
        B_i[ind + 3]) for ind in range(0, 64, 4)]
    for j in range(16, 68):
        # a = (P_1(W[- 16] ^ W[- 9] ^ (rotate_left(W[- 3], 15))) ^ (rotate_left(W[- 13], 7)) ^ W[- 6])
        W.append(P_1(W[- 16] ^ W[- 9] ^ (rotate_left(W[- 3], 15))) ^ (rotate_left(W[- 13], 7)) ^ W[- 6])

    W_1 = [W[j] ^ W[j + 4] for j in range(64)]

    A, B, C, D, E, F, G, H = V_i
    for j in range(0, 64):
        SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ (rotate_left(A, 12))
        TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D, E, F, G, H = TT1, A, rotate_left(B, 9) & 0xffffffff, C, P_0(
            TT2) & 0xffffffff, E, rotate_left(F, 19) & 0xffffffff, G
    return [A ^ V_i[0], B ^ V_i[1], C ^ V_i[2],
            D ^ V_i[3], E ^ V_i[4], F ^ V_i[5], G ^ V_i[6], H ^ V_i[7]]


def hash_msg(msg):
    # print(msg)
    len1 = len(msg)
    msg.append(0x80)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    msg.extend([0] * (range_end - reserve1))
    bit_length = len1 * 8
    msg.extend(struct.pack(">Q", bit_length))
    # print(msg)
    B = (msg[i:i + 64] for i in range(0, len(msg), 64))
    y = reduce(CF, B, IV)
    return "".join(map(lambda x: '%08x' % x, y))


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
    return msg.decode(decode) if isinstance(msg, (bytes, bytearray)) else msg


def hex2byte(msg):
    """
    16进制字符串转换成byte列表
    :param msg:
    :return:
    """
    ml = len(msg)
    if (ml & 1) != 0:
        msg = '0' + msg
    return list(bytes.fromhex(msg))


def byte2hex(msg):  # byte数组转换成16进制字符串
    return "".join(map(lambda each: '%02x' % each, msg))


def Hash_sm3(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return hash_msg(msg_byte)


hexdigest = Hash_sm3


def digest(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return bytes.fromhex(hash_msg(msg_byte))


def KDF(Z, klen):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    klen = int(klen)
    rcnt = int(ceil(klen / 32))
    Zin = hex2byte(Z)
    Ha = "".join(map(lambda ct: hash_msg(Zin + hex2byte('%08x' % ct)), range(1, rcnt + 1)))
    return Ha[0: klen * 2]


class SM3Type(object):
    name = 'SM3'
    digest_size = 64
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
