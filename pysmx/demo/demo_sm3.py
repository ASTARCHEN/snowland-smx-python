#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: demo_sm3.py
# @time: 2019/5/6 15:18
# @Software: PyCharm


__author__ = 'A.Star'

import hashlib
from pysmx.crypto import hashlib as sm3hashlib
import time
s = b'abc'
# s = bytes.fromhex(''.join(['%02x' % i for i in range(256)])) * 1024 * 10

starttime = time.clock()
sha256 = hashlib.sha256()
sha256.update(s)
a = sha256.hexdigest()
endtime1 = time.clock()
sm3 = sm3hashlib.sm3()
sm3.update(s)
b = sm3.hexdigest()
print(b)
endtime2 = time.clock()
b = sm3.digest()
print(b)
print(endtime1-starttime, endtime2-endtime1)
