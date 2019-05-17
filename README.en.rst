===================
snowland-smx-python
===================
#. SM2
    gm signature
    a. generate keypair

>>> from pysmx.SM2 import generate_keypair
>>> pk, sk = generate_keypair()

    #. signature

>>> from pysmx.SM2 import Sign
>>> len_para = 64
>>> sig = Sign("hello", sk, '12345678abcdef', len_para)

    #. verify

>>> from pysmx.SM2 import Verify
>>> len_para = 64
>>> Verify(sig, "hello", pk, len_para)

    #. encrpto

>>> from pysmx.SM2 import Encrypt
>>> e = b'hello'
>>> len_para = 64
>>> C = Encrypt(e, pk, len_para, 0)  # 0 means var e is not a hex string

    #. decrpto

>>> from  pysmx.SM2 import Decrypt
>>> len_para = 64
>>> m = Decrypt(C, sk, len_para)

#. SM3
    hash
    a. method 1:

>>> from pysmx.SM3 import SM3
>>> sm3 = SM3()
>>> sm3.update('abc')
>>> sm3.hexdigest()

    #. method 2:

>>> from pysmx.SM3 import hash_msg
>>> s = 'abc'
>>> hash_msg(s)

#. SM4
    block encrpto
    a. encrpto

>>> from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
>>> key_data = b'hello word errrr...'  # 16 bytes at least
>>> sm4 = Sm4()
>>> input_data = [1,2,3]
>>> sm4.sm4_set_key(key_data, ENCRYPT)
>>> msg = sm4.sm4_crypt_ecb()

    b. decryto

>>> from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
>>> key_data = b'hello word errrr...'  # 16 bytes at least
>>> sm4 = Sm4()
>>> sm4.sm4_set_key(key_data, DECRYPT)
>>> sm4.sm4_crypt_ecb(msg)

#. ZUC
    waiting for update
