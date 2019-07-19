#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 河北雪域网络科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.snowland.ltd
# @file: hashlib.py
# @time: 2018/11/17 23:13
# @Software: PyCharm


from pysmx.SM3 import SM3Type
__always_supported = ('sm3', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                      'blake2b', 'blake2s',
                      'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
                      'shake_128', 'shake_256')


algorithms_guaranteed = set(__always_supported)
algorithms_available = set(__always_supported)

__all__ = __always_supported + ('new', 'algorithms_guaranteed',
                                'algorithms_available', 'pbkdf2_hmac')


__builtin_constructor_cache = {'SM3':SM3Type, 'sm3':SM3Type}

def __get_builtin_constructor(name):
    cache = __builtin_constructor_cache
    constructor = cache.get(name)
    if constructor is not None:
        return constructor
    try:
        if name in ('sm3', 'SM3'):
            from pysmx.SM3 import SM3Type
            cache['SM3'] = cache['sm3'] = SM3Type
        elif name in ('SHA1', 'sha1'):
            import _sha1
            cache['SHA1'] = cache['sha1'] = _sha1.sha1
        elif name in ('MD5', 'md5'):
            import _md5
            cache['MD5'] = cache['md5'] = _md5.md5
        elif name in ('SHA256', 'sha256', 'SHA224', 'sha224'):
            import _sha256
            cache['SHA224'] = cache['sha224'] = _sha256.sha224
            cache['SHA256'] = cache['sha256'] = _sha256.sha256
        elif name in ('SHA512', 'sha512', 'SHA384', 'sha384'):
            import _sha512
            cache['SHA384'] = cache['sha384'] = _sha512.sha384
            cache['SHA512'] = cache['sha512'] = _sha512.sha512
        elif name in ('blake2b', 'blake2s'):
            import _blake2
            cache['blake2b'] = _blake2.blake2b
            cache['blake2s'] = _blake2.blake2s
        elif name in {'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
                      'shake_128', 'shake_256'}:
            import _sha3
            cache['sha3_224'] = _sha3.sha3_224
            cache['sha3_256'] = _sha3.sha3_256
            cache['sha3_384'] = _sha3.sha3_384
            cache['sha3_512'] = _sha3.sha3_512
            cache['shake_128'] = _sha3.shake_128
            cache['shake_256'] = _sha3.shake_256
    except ImportError:
        pass  # no extension module, this hash is unsupported.

    constructor = cache.get(name)
    if constructor is not None:
        return constructor

    raise ValueError('unsupported hash type ' + name)


def __get_openssl_constructor(name):
    if name in {'blake2b', 'blake2s'}:
        # Prefer our blake2 implementation.
        return __get_builtin_constructor(name)
    try:
        f = getattr(_hashlib, 'openssl_' + name)
        # Allow the C module to raise ValueError.  The function will be
        # defined but the hash not actually available thanks to OpenSSL.
        f()
        # Use the C function directly (very fast)
        return f
    except (AttributeError, ValueError):
        return __get_builtin_constructor(name)


def __py_new(name, data=b'', **kwargs):
    """new(name, data=b'', **kwargs) - Return a new hashing object using the
    named algorithm; optionally initialized with data (which must be bytes).
    """
    return __get_builtin_constructor(name)(data, **kwargs)


def __hash_new(name, data=b'', **kwargs):
    """new(name, data=b'') - Return a new hashing object using the named algorithm;
    optionally initialized with data (which must be bytes).
    """
    if name in {'blake2b', 'blake2s'}:
        # Prefer our blake2 implementation.
        # OpenSSL 1.1.0 comes with a limited implementation of blake2b/s.
        # It does neither support keyed blake2 nor advanced features like
        # salt, personal, tree hashing or SSE.
        return __get_builtin_constructor(name)(data, **kwargs)
    try:
        return _hashlib.new(name, data)
    except ValueError:
        # If the _hashlib module (OpenSSL) doesn't support the named
        # hash, try using our builtin implementations.
        # This allows for SHA224/256 and SHA384/512 support even though
        # the OpenSSL library prior to 0.9.8 doesn't provide them.
        return __get_builtin_constructor(name)(data)


try:
    import _hashlib
    new = __hash_new
    __get_hash = __get_openssl_constructor
    algorithms_available = algorithms_available.union(
            _hashlib.openssl_md_meth_names)
except ImportError:
    new = __py_new
    __get_hash = __get_builtin_constructor


_trans_5C = bytes((x ^ 0x5C) for x in range(256))
_trans_36 = bytes((x ^ 0x36) for x in range(256))

def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    """Password based key derivation function 2 (PKCS #5 v2.0)

    This Python implementations based on the hmac module about as fast
    as OpenSSL's PKCS5_PBKDF2_HMAC for short passwords and much faster
    for long passwords.
    """
    if not isinstance(hash_name, str):
        raise TypeError(hash_name)

    if not isinstance(password, (bytes, bytearray)):
        password = bytes(memoryview(password))
    if not isinstance(salt, (bytes, bytearray)):
        salt = bytes(memoryview(salt))

    # Fast inline HMAC implementation
    inner = new(hash_name)
    outer = new(hash_name)
    blocksize = getattr(inner, 'block_size', 64)
    if len(password) > blocksize:
        password = new(hash_name, password).digest()
    password = password + b'\x00' * (blocksize - len(password))
    inner.update(password.translate(_trans_36))
    outer.update(password.translate(_trans_5C))

    def prf(msg, inner=inner, outer=outer):
        # PBKDF2_HMAC uses the password as key. We can re-use the same
        # digest objects and just update copies to skip initialization.
        icpy = inner.copy()
        ocpy = outer.copy()
        icpy.update(msg)
        ocpy.update(icpy.digest())
        return ocpy.digest()

    if iterations < 1:
        raise ValueError(iterations)
    if dklen is None:
        dklen = outer.digest_size
    if dklen < 1:
        raise ValueError(dklen)

    dkey = b''
    loop = 1
    from_bytes = int.from_bytes
    while len(dkey) < dklen:
        prev = prf(salt + loop.to_bytes(4, 'big'))
        # endianess doesn't matter here as long to / from use the same
        rkey = int.from_bytes(prev, 'big')
        for i in range(iterations - 1):
            prev = prf(prev)
            # rkey = rkey ^ prev
            rkey ^= from_bytes(prev, 'big')
        loop += 1
        dkey += rkey.to_bytes(inner.digest_size, 'big')

    return dkey[:dklen]

try:
    # OpenSSL's scrypt requires OpenSSL 1.1+
    from _hashlib import scrypt
except ImportError:
    pass


for __func_name in __always_supported:
    # try them all, some may not work due to the OpenSSL
    # version not supporting that algorithm.
    try:
        globals()[__func_name] = __get_hash(__func_name)
    except ValueError:
        import logging
        logging.exception('code for hash %s was not found.', __func_name)


# Cleanup locals()
del __always_supported, __func_name, __get_hash
del __py_new, __hash_new, __get_openssl_constructor
