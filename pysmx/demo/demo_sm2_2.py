#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: demo_sm2.py
# @time: 2019/3/21 11:29
# @Software: PyCharm


__author__ = 'A.Star'


from pysmx.SM2 import *
letterlist = "0123456789abcdef"

from random import choices


def get_random_str(k):
    return ''.join(choices(letterlist, k))


if __name__ == '__main__':
    # len_para = int(Fp // 4)
    # print(len_para)
    len_para = 64
    e = get_random_str(len_para)
    hash_algorithm = 'sm3'
    pk, sk = generate_keypair(len_para)
    sig = Sign("你好", sk, '12345678', len_para)
    print(Verify(sig, "你好", pk, len_para))
    e = "你好"
    print('M = %s' % e)
    C = Encrypt(e, pk, len_para, 0, hash_algorithm=hash_algorithm)
    print('C = %s' % C)
    print('Decrypt')
    m = Decrypt(C, sk, len_para, hash_algorithm=hash_algorithm)
    M = bytes.fromhex(m)
    print(M.decode())

    # e  = '00ce5d9489d867867096326f3842323ab0a2f7f893181bae4dc9d4cd7ed50f31'
    # D  = '1d06dc143f1725f7eeae8a0ae94ebc62fbe4407c99a90950e46d29e7645000cb'
    # K  = '8e00000000000000000000000000000000000000000000000000000000000000'
    # Px = '000000000000000000000000000000000000000000000000f100000000000000'
    # Py = '0000000000000000000000000000000000000000000000000000000000000000'
    # print(Verify(D+K, e, Px+Py, len_para))
