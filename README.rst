===================
snowland-smx-python
===================
1. SM2
  国密公钥加解密签名验签
  a. 密钥生成
  >>> from pysmx.SM2 import generate_keypair
  >>> pk, sk = generate_keypair()
  #. 签名
  >>> from pysmx.SM2 import Sign
  >>> len_para = 64
  >>> sig = Sign("你好", sk, '12345678abcdef', len_para)
  #. 验签
  >>> from pysmx.SM2 import Verify
  >>> len_para = 64
  >>> Verify(sig, "你好", pk, len_para)
  #. 加密
  >>> from pysmx.SM2 import Encrypt
  >>> e = b'hello'
  >>> len_para = 64
  >>> C = Encrypt(e, pk, len_para, 0)  # 此处的1代表e是否是16进制字符串
  #. 解密
  >>> from  pysmx.SM2 import Decrypt
  >>> len_para = 64
  >>> m = Decrypt(C, sk, len_para)

#. SM3
  国密哈希
  a. 方法1:
  >>> from pysmx.SM3 import SM3
  >>> sm3 = SM3()
  >>> sm3.update('abc')
  >>> sm3.hexdigest()
  #. 方法2:
  >>> from pysmx.SM3 import hash_msg
  >>> s = 'abc'
  >>> hash_msg(s)
#. SM4
  国密私钥加解密
  a. 加密
  >>> from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
  >>> key_data = b'hello word errrr...'  # 至少16字节
  >>> sm4 = Sm4()
  >>> input_data = [1,2,3]
  >>> sm4.sm4_set_key(key_data, ENCRYPT)
  >>> msg = sm4.sm4_crypt_ecb()
  b. 解密
  >>> from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
  >>> key_data = b'hello word errrr...'  # 至少16字节
  >>> sm4 = Sm4()
  >>> sm4.sm4_set_key(key_data, DECRYPT)
  >>> sm4.sm4_crypt_ecb(msg)

#. ZUC
  waiting for update
