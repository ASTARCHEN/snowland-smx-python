#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: _SM2.py
# @time: 2018/12/03 15:11
# @Software: PyCharm


from functools import reduce
from random import choices, randint
from pysmx.SM3 import KDF
from pysmx.crypto import hashlib
from collections import namedtuple
from pysmx import SM3
from functools import reduce
import time
import random

# 选择素域，设置椭圆曲线参数
sm2_N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
sm2_P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
sm2_G = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'  # G点
sm2_G_number = int(sm2_G, 16)
sm2_a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
sm2_b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
sm2_a_3 = (sm2_a + 3) % sm2_P  # 倍点用到的中间值
Fp = 256
letterlist = "0123456789abcdef"


# sm2_N = int('BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677', 16)
# sm2_P = int('BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F', 16)
# sm2_G = '4AD5F7048DE709AD51236DE65E4D4B482C836DC6E410664002BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2'# G点
# sm2_a = int('BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985',16)
# sm2_b = int('1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1',16)
# sm2_a_3 = (sm2_a + 3) % sm2_P # 倍点用到的中间值
# Fp = 192

def get_random_str(n: int, allow_chars: str = letterlist):
    return ''.join(choices(allow_chars, k=n))


def modular_power(a, n, p):
    """
    计算a^ n % p
    if n == 0:
        return 1
    elif n == 1:
        return a % p
    temp = a * a % p
    if n & 1:
        return a % p * modular_power(temp, n // 2, p) % p
    else:
        return (modular_power(temp, n // 2, p)) % p
    原文：https://blog.csdn.net/qq_36921652/article/details/79368299
    """
    return pow(a, n, p)


def is_prime(number: (str, int), itor=10):
    if not isinstance(number, int):
        number = int(number)
    for i in range(itor):
        a = randint(1, number - 1)
        if modular_power(a, number - 1, number) != 1:
            return False
    return True


def get_hash(algorithm_name, message, Hexstr=0, encoding='utf-8'):
    if hasattr(hashlib, algorithm_name):
        f = getattr(hashlib, algorithm_name)()
    else:
        raise ValueError('method does not exists')
    if Hexstr:
        message = bytes.fromhex(message)
    if isinstance(message, (bytes, bytearray)):
        f.update(message)
    else:
        f.update(bytes(message, encoding=encoding))
    return f.hexdigest()


def kG(k, Point, len_para):
    """
    kP运算
    :param k:
    :param Point:
    :param len_para:
    :return:
    """
    Point += '1'
    Temp = reduce(
        lambda x, y: AddPoint(DoublePoint(x, len_para), Point, len_para) if y is '1' else DoublePoint(x, len_para),
        bin(k)[3:], Point)
    return ConvertJacb2Nor(Temp, len_para)


def DoublePoint(Point, len_para, P=sm2_P):
    """
    倍点
    :param Point:
    :param len_para:
    :param P:
    :return:
    """
    length = len(Point)
    len_2 = 2 * len_para
    if length < len_2:
        return None
    else:
        x1 = int(Point[0:len_para], 16)
        y1 = int(Point[len_para:len_2], 16)
        z1 = 1 if length == len_2 else int(Point[len_2:], 16)
        T6 = (z1 * z1) % P
        T2 = (y1 * y1) % P
        T3 = (x1 + T6) % P
        T4 = (x1 - T6) % P
        T1 = (T3 * T4) % P
        T3 = (y1 * z1) % P
        T4 = (T2 * 8) % P
        T5 = (x1 * T4) % P
        T1 = (T1 * 3) % P
        T6 = (T6 * T6) % P
        T6 = (sm2_a_3 * T6) % P
        T1 = (T1 + T6) % P
        z3 = (T3 + T3) % P
        T3 = (T1 * T1) % P
        T2 = (T2 * T4) % P
        x3 = (T3 - T5) % P
        T4 = (T5 + ((T5 + P) >> 1) - T3) % P if T5 % 2 else (T5 + (T5 >> 1) - T3) % P
        T1 = (T1 * T4) % P
        y3 = (T1 - T2) % P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (x3, y3, z3)


def AddPoint(P1, P2, len_para, P=sm2_P):
    """点加函数
    :param P1 为Jacobian加重射影坐标
    :param P2 为仿射坐标即z=1
    """
    len_2 = 2 * len_para
    l1 = len(P1)
    l2 = len(P2)
    if (l1 < len_2) or (l2 < len_2):
        return None
    else:
        X1 = int(P1[0:len_para], 16)
        Y1 = int(P1[len_para:len_2], 16)
        Z1 = 1 if l1 == len_2 else int(P1[len_2:], 16)
        x2 = int(P2[0:len_para], 16)
        y2 = int(P2[len_para:len_2], 16)

        T1 = (Z1 * Z1) % P
        T2 = (y2 * Z1) % P
        T3 = (x2 * T1) % P
        T1 = (T1 * T2) % P
        T2 = (T3 - X1) % P
        T3 = (T3 + X1) % P
        T4 = (T2 * T2) % P
        T1 = (T1 - Y1) % P
        Z3 = (Z1 * T2) % P
        T2 = (T2 * T4) % P
        T3 = (T3 * T4) % P
        T5 = (T1 * T1) % P
        T4 = (X1 * T4) % P
        X3 = (T5 - T3) % P
        T2 = (Y1 * T2) % P
        T3 = (T4 - X3) % P
        T1 = (T1 * T3) % P
        Y3 = (T1 - T2) % P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (X3, Y3, Z3)


def ConvertJacb2Nor(Point, len_para, P=sm2_P):
    """Jacobian加重射影坐标转换成仿射坐标"""
    len_2 = 2 * len_para
    x = int(Point[0:len_para], 16)
    y = int(Point[len_para:len_2], 16)
    z = int(Point[len_2:], 16)
    # z_inv = Inverse(z, P)
    z_inv = pow(z, P - 2, P)
    z_invSquar = (z_inv * z_inv) % P
    z_invQube = (z_invSquar * z_inv) % P
    x_new = (x * z_invSquar) % P
    y_new = (y * z_invQube) % P
    z_new = (z * z_inv) % P
    if z_new == 1:
        form = '%%0%dx' % len_para
        form = form * 2
        return form % (x_new, y_new)
    else:
        print("Point at infinity!!!!!!!!!!!!")
        return None


def Inverse(data, M, len_para=64):
    """ 求逆, 可用pow（）代替"""
    tempM = M - 2
    mask_str = '8' + '0' * (len_para - 1)
    mask = int(mask_str, 16)
    tempA = 1
    tempB = data

    for i in range(len_para * 4):
        tempA = (tempA * tempA) % M
        if (tempM & mask) != 0:
            tempA = (tempA * tempB) % M
        mask = mask >> 1

    return tempA


def Verify(Sign, E, PA, len_para=64, Hexstr=0, encoding='utf-8'):
    """
    验签函数
    :param Sign: 签名 r||s
    :param E: E消息hash
    :param PA: PA公钥
    :param len_para:
    :return:
    """
    if isinstance(Sign, str):
        r = int(Sign[0:len_para], 16)
        s = int(Sign[len_para:2 * len_para], 16)
    elif isinstance(Sign, bytes):
        r = int(Sign.hex()[:len_para], 16)
        s = int(Sign.hex()[len_para:2 * len_para], 16)

    if Hexstr:
        e = int(E, 16)  # 输入消息本身是16进制字符串
    else:
        if isinstance(E, str):
            E = E.encode(encoding)
        E = E.hex()  # 消息转化为16进制字符串
        e = int(E, 16)

    if isinstance(PA, str):
        pass
    elif isinstance(PA, (bytes, bytearray)):
        PA = PA.hex()
    else:
        raise ValueError('Typeof PA must be string or bytes')
    t = (r + s) % sm2_N
    if t == 0:
        return 0

    P1 = kG(s, sm2_G, len_para)
    P2 = kG(t, PA, len_para)
    # print(P1)
    # print(P2)
    if P1 == P2:
        P1 += '1'
        P1 = DoublePoint(P1, len_para)
    else:
        P1 += '1'
        P1 = AddPoint(P1, P2, len_para)
        P1 = ConvertJacb2Nor(P1, len_para)

    x = int(P1[0:len_para], 16)
    return r == ((e + x) % sm2_N)


def Sign(E, DA, K, len_para, Hexstr=0, encoding='utf-8'):
    """签名函数
     :param E 消息的hash, 16进制字符串
     :param DA私钥, 16进制字符串
     :param K 随机数, 16进制字符串
     """
    if Hexstr:
        e = int(E, 16)  # 输入消息本身是16进制字符串
    else:
        if isinstance(E, str):
            E = E.encode(encoding)
        E = E.hex()  # 消息转化为16进制字符串
        e = int(E, 16)
    if isinstance(DA, str):
        d = int(DA, 16)
    elif isinstance(DA, (bytes, bytearray)):
        d = int(DA.hex(), 16)
    else:
        raise ValueError('DA must be str or bytes')
    k = int(K, 16)

    P1 = kG(k, sm2_G, len_para)

    x = int(P1[:len_para], 16)
    R = (e + x) % sm2_N
    if R == 0 or R + k == sm2_N:
        return None
    d_1 = pow(d + 1, sm2_N - 2, sm2_N)
    S = (d_1 * (k + R) - R) % sm2_N
    s = '%0{}x%0{}x'.format(len_para, len_para) % (R, S) if S else None
    return bytes.fromhex(s)


def Encrypt(M, PA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3'):
    """
    加密函数
    :param M: 消息
    :param PA: PA公钥
    :param len_para: 目前固定为64
    :param Hexstr: M是否是hex字符串
    :param encoding: 若M不是16进制字符串
    :param hash_algorithm:
    :return:
    """
    if Hexstr:
        msg = M  # 输入消息本身是16进制字符串
    else:
        if isinstance(M, str):
            msg = M.encode(encoding)
        else:
            msg = M
        msg = msg.hex()  # 消息转化为16进制字符串
    if isinstance(PA, str):
        pass
    elif isinstance(PA, (bytes, bytearray)):
        PA = PA.hex()
    else:
        raise ValueError('Typeof PA must be string or bytes')
    k = get_random_str(len_para)
    # k = '59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21'
    # k = '384F30353073AEECE7A1654330A96204D37982A3E15B2CB5'
    C1 = kG(int(k, 16), sm2_G, len_para)
    # print('C1 = %s'%C1)
    xy = kG(int(k, 16), PA, len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:2 * len_para]
    ml = len(msg)
    t = KDF(xy, ml / 2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % ml
        C2 = form % (int(msg, 16) ^ int(t, 16))
        # print('C2 = %s'% C2)
        # print('%s%s%s'% (x2,msg,y2))
        C3 = get_hash(hash_algorithm, '%s%s%s' % (x2, msg, y2), Hexstr=1)
        # print('C3 = %s' % C3)
        return bytes.fromhex('%s%s%s' % (C1, C3, C2))


def Decrypt(C, DA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3'):
    """
    解密函数，
    :param C 密文（16进制字符串）
    :param DA 私钥
    :param len_para 长度，目前只支持64
    """
    f = getattr(hashlib, hash_algorithm)()
    if isinstance(DA, str):
        pass
    elif isinstance(DA, (bytes, bytearray)):
        DA = DA.hex()
    else:
        raise ValueError('DA must be str or bytes')
    len_2 = 2 * len_para
    len_3 = len_2 + f.digest_size * 2
    if not Hexstr:
        if isinstance(C, bytes):
            C = C.hex()

    C1 = C[0:len_2]
    C3 = C[len_2:len_3]
    C2 = C[len_3:]
    xy = kG(int(DA, 16), C1, len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:len_2]
    cl = len(C2)
    # print(cl)
    t = KDF(xy, cl / 2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2, 16) ^ int(t, 16))
        # print('M = %s' % M)

        u = get_hash(hash_algorithm, '%s%s%s' % (x2, M, y2), 1)
        return bytes.fromhex(M) if u == C3 else None


KeyPair = namedtuple('KeyPair', ['publicKey', 'privateKey'])


def generate_keypair(len_param=64):
    d = get_random_str(len_param)
    PA = kG(int(d, 16), sm2_G, len_param)
    return KeyPair(bytes.fromhex(PA), bytes.fromhex(d))


if __name__ == '__main__':
    print(generate_keypair(64))
