from math import ceil
import time
from functools import reduce

BIT_BLOCK_H = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF]
BIT_BLOCK_L = [0x0, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
BIT_EACH = [1, 2, 4, 8, 16, 32, 64, 128, 256]

IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
IV = int(IV.replace(" ", ""), 16)
IV = [(IV >> ((7 - i) * 32)) & 0xFFFFFFFF for i in range(8)]


def rotate_left(a, k):
    k %= 32
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))


T_j = [0x79cc4519] * 16
T_j.extend([0x7a879d8a] * 48)


def FF_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG_j(X, Y, Z, j):
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | ((~ X) & Z)


def P_0(X):
    return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))


def P_1(X):
    return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))


def CF(V_i, B_i):
    W = [(B_i[ind] << 24) + (B_i[ind + 1] << 16) + (B_i[ind + 2] << 8) + (B_i[ind + 3]) for ind in range(0, 64, 4)]
    for j in range(16, 68):
        W.append(P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6])
    W_1 = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V_i

    for j in range(0, 64):
        SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ (rotate_left(A, 12))
        TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D, E, F, G, H = TT1, A, rotate_left(B, 9) & 0xffffffff, C, P_0(
            TT2) & 0xffffffff, E, rotate_left(F, 19) & 0xffffffff, G
    V_i[0] ^= A
    V_i[1] ^= B
    V_i[2] ^= C
    V_i[3] ^= D
    V_i[4] ^= E
    V_i[5] ^= F
    V_i[6] ^= G
    V_i[7] ^= H
    return V_i


def hash_msg(msg):
    # print(msg)
    len1 = len(msg)
    msg.append(0x80)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    msg.extend([0] * (range_end - reserve1))
    bit_length = len1 * 8
    bit_length_str = []
    for i in range(8):
        bit_length, t = divmod(bit_length, 0x100)
        bit_length_str.insert(0, t)
    msg.extend(bit_length_str)
    # print(msg)
    B = [msg[i:i + 64] for i in range(0, len(msg), 64)]
    y = reduce(CF, B, IV)
    return "".join(['%08x' % i for i in y])


def str2byte(msg):  # 字符串转换成byte数组
    msg_bytearray = msg.encode('utf-8') if isinstance(msg, str) else msg
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


def hex2byte(msg):  # 16进制字符串转换成byte列表
    ml = len(msg)
    if ml % 2 != 0:
        msg = '0' + msg
    return list(bytes.fromhex(msg))


def byte2hex(msg):  # byte数组转换成16进制字符串
    return "".join(['%02x' % each for each in msg])


def Hash_sm3(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2byte(msg)
    return hash_msg(msg_byte)


def KDF(Z, klen):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    klen = int(klen)
    rcnt = int(ceil(klen / 32))
    Zin = hex2byte(Z)
    Ha = "".join([hash_msg(Zin + hex2byte('%08x' % ct)) for ct in range(1, rcnt + 1)])
    return Ha[0: klen * 2]


if __name__ == '__main__':
    a = bytes("abc", encoding='utf8')
    st = time.clock()
    y = Hash_sm3("abc", 0)
    et = time.clock()
    print("sm3:", y)
    print("time:", et - st)
    # print("\n\n")
    klen = 19
    print(KDF("57E7B63623FAE5F08CDA468E872A20AFA03DED41BF1403770E040DC83AF31A67991F2B01EBF9EFD8881F0A0493000603", klen))
