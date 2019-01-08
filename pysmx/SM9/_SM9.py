# #not /usr/bin/env python
# # -*- coding: utf-8 -*-
# # @Author  : 河北雪域网络科技有限公司 A.Star
# # @contact: astar@snowland.ltd
# # @site: www.snowland.ltd
# # @file: _SM9.py
# # @time: 2018/10/20 17:23
# # @Software: PyCharm
#
#
# SM9_q = [
# 	0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x45,
# 	0x21,0xF2,0x93,0x4B,0x1A,0x7A,0xEE,0xDB,0xE5,0x6F,0x9B,0x27,0xE3,0x51,0x45,0x7D
# ]
#
# SM9_N = [
# 	0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x44,
# 	0x49,0xF2,0x93,0x4B,0x18,0xEA,0x8B,0xEE,0xE5,0x6E,0xE1,0x9C,0xD6,0x9E,0xCF,0x25
# ]
#
# SM9_P1x = [
# 	0x93,0xDE,0x05,0x1D,0x62,0xBF,0x71,0x8F,0xF5,0xED,0x07,0x04,0x48,0x7D,0x01,0xD6,
# 	0xE1,0xE4,0x08,0x69,0x09,0xDC,0x32,0x80,0xE8,0xC4,0xE4,0x81,0x7C,0x66,0xDD,0xDD
# ]
#
# SM9_P1y = [
# 	0x21,0xFE,0x8D,0xDA,0x4F,0x21,0xE6,0x07,0x63,0x10,0x65,0x12,0x5C,0x39,0x5B,0xBC,
# 	0x1C,0x1C,0x00,0xCB,0xFA,0x60,0x24,0x35,0x0C,0x46,0x4C,0xD7,0x0A,0x3E,0xA6,0x16
# ]
#
# SM9_P2 = [
# 	0x85,0xAE,0xF3,0xD0,0x78,0x64,0x0C,0x98,0x59,0x7B,0x60,0x27,0xB4,0x41,0xA0,0x1F,
# 	0xF1,0xDD,0x2C,0x19,0x0F,0x5E,0x93,0xC4,0x54,0x80,0x6C,0x11,0xD8,0x80,0x61,0x41,
# 	0x37,0x22,0x75,0x52,0x92,0x13,0x0B,0x08,0xD2,0xAA,0xB9,0x7F,0xD3,0x4E,0xC1,0x20,
# 	0xEE,0x26,0x59,0x48,0xD1,0x9C,0x17,0xAB,0xF9,0xB7,0x21,0x3B,0xAF,0x82,0xD6,0x5B,
# 	0x17,0x50,0x9B,0x09,0x2E,0x84,0x5C,0x12,0x66,0xBA,0x0D,0x26,0x2C,0xBE,0xE6,0xED,
# 	0x07,0x36,0xA9,0x6F,0xA3,0x47,0xC8,0xBD,0x85,0x6D,0xC7,0x6B,0x84,0xEB,0xEB,0x96,
# 	0xA7,0xCF,0x28,0xD5,0x19,0xBE,0x3D,0xA6,0x5F,0x31,0x70,0x15,0x3D,0x27,0x8F,0xF2,
# 	0x47,0xEF,0xBA,0x98,0xA7,0x1A,0x08,0x11,0x62,0x15,0xBB,0xA5,0xC9,0x99,0xA7,0xC7
# ]
#
# SM9_t = [
# 	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
# 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x00,0x58,0xF9,0x8A
# ]
#
# SM9_a = [
# 	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
# 	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
# ]
#
# SM9_b = [
# 	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
# 	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05
# ]
# class SM9:
#     def signature(message, pk, sk):
#         hasException = True
#         dsa = None
#         # epoint *
#         S = None
#         h2 = None
#         r = None
#         l = None
#         tmp = None
#         zero = None
#
#         # Step1 : g = e(P1, Ppub-s)
#         cin_ecn2_byte128(Ppubs, masterPublicKey.c_str())
#         if (not ZZN12::calcRatePairing(g, Ppubs, param_P1, param_t, norm_X) ) {
#         mErrorNum = SM9_ERROR_CALC_RATE
#         goto END
#         }
#
#         # ifdef SELF_CHECK
#         gHex = YHex::Encode(g.toByteArray())
#         # endif
#
#         while True:
#             # ifdef SELF_CHECK
#             rHex = int("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16)
#             # else
#             # Step2: generate r
#             bigrand(param_N, r)
#             # endif
#
#             # Step3 : calculate w=g^r
#             w = np.pow(g, r)
#             sw = w.toByteArray()
#
#             # ifdef SELF_CHECK
#             wHex = YHex::Encode(sw)
#
#             # endif
#
#             # Step4 : calculate h=H2(M or w,N)
#             h = KGC::H2(data, sw)
#             cin_big(h2, h.c_str(), h.length())
#
#             # ifdef SELF_CHECK
#             h2Hex = YHex::Encode(h)
#             # endif
#
#             # Step5 : l=(r-h)mod N
#             subtract(r, h2, l)
#             divide(l, param_N, tmp)
#             while (mr_compare(l, zero) < 0):
#                 add(l, param_N, l)
#                 if (mr_compare(l, zero) not = 0):
#                     break
#
#
#                 # Step6 : S=[l]dSA=(xS,yS)
#                 cin_epoint(dsa, prikey.c_str())
#                 ecurve_mult(l, dsa, S)
#                 s = cout_epoint(S)
#
#                 # Step7 : signature=(h,s)
#                 signature = Signature(h, s)
#
#                 hasException = False
#
#             END:
#                 release_epoint(dsa)
#                 release_epoint(S)
#                 release_ecn2(Ppubs)
#                 release_big(h2)
#                 release_big(r)
#                 release_big(l)
#                 release_big(tmp)
#                 release_big(zero)
#
#                 if (hasException) {
#                 throw
#                 exception(getErrorMsg().c_str())
#
#             return signature
#
#         return signature
#
#
# def SM9_unwrap_key(_type, key, enced_key, sk):
#     ret = 0
# 	# p = SM9_get0_prime()
# 	wbuf = [0] * 384
# 	out = key
# 	outlen = keylen
# 	counter = [0, 0, 0, 1]
# 	dgst = [0] * 64
# 	if _type == 'NID_sm9kdf_with_sm3':
#         # TODO
# 		# kdf_md = EVP_sm3()
#         pass
# 	elif _type == 'NID_sm9kdf_with_sha256':
#         # todo
# 		# kdf_md = EVP_sha256()
# 		pass
#
# 	# TODO check init
#
# 	# parse C on E(F_p)
# 	if (not EC_POINT_oct2point(group, C, enced_key, enced_len, bn_ctx)) {
# 		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE)
# 		goto end
# 	}
#
# 	# /* parse de on E'(E_p^2) */
# 	if (not point_from_octets(&de, ASN1_STRING_get0_data(sk->privatePoint), p, bn_ctx)):
# 		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE)
#
#
# 	# /* w = e(C, de) */
# 	if (not rate_pairing(w, &de, C, bn_ctx)):
# 		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE)
#
# 	if (not fp12_to_bin(w, wbuf)):
# 		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE)
#
#
# 	# /* K = KDF(C or w or ID_B, klen) */
# 	while (outlen > 0):
# 		if (not EVP_DigestInit_ex(md_ctx, kdf_md, NULL)
# 			 or  not EVP_DigestUpdate(md_ctx, enced_key + 1, enced_len - 1)
# 			 or  not EVP_DigestUpdate(md_ctx, wbuf, sizeof(wbuf))
# 			 or  not EVP_DigestUpdate(md_ctx, ASN1_STRING_get0_data(sk->identity), ASN1_STRING_length(sk->identity))
# 			 or  not EVP_DigestUpdate(md_ctx, counter, sizeof(counter))
# 			 or  not EVP_DigestFinal_ex(md_ctx, dgst, &len)):
# 			SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EVP_LIB)
#
#
#
# 		if len > outlen:
# 			len = outlen
# 		# todo check memcpy(out, dgst, len)
#         dgst[:len] = dgst[:len]
# 		out += len
# 		outlen -= len
# 		counter[3]+=1
#
#
# 	return ret
#
# int SM9_wrap_key(keytype,
# 	unsigned char *key, size_t keylen,
# 	unsigned char *enced_key, size_t *enced_len,
# 	SM9PublicParameters *mpk, const char *id, size_t idlen)
#
#     # NID_sm9kdf_with_sm3
#
# 	int ret = 0
# 	EC_GROUP *group = NULL
# 	EC_POINT *Ppube = NULL
# 	EC_POINT *C = NULL
# 	EVP_MD_CTX *md_ctx = NULL
# 	BN_CTX *bn_ctx = NULL
# 	BIGNUM *r = NULL
# 	BIGNUM *h = NULL
# 	fp12_t w
# 	const EVP_MD *kdf_md
# 	const EVP_MD *hash1_md
# 	const BIGNUM *p = SM9_get0_prime()
# 	const BIGNUM *n = SM9_get0_order()
# 	unsigned char cbuf[65]
# 	unsigned char wbuf[384]
# 	unsigned char dgst[64]
# 	int all
#
# 	switch (type) {
# 	case NID_sm9kdf_with_sm3:
# 		kdf_md = EVP_sm3()
# 		break
# 	case NID_sm9kdf_with_sha256:
# 		kdf_md = EVP_sha256()
# 		break
# 	default:
# 		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_DIGEST_TYPE)
# 		return 0
# 	}
#
# 	if (keylen > EVP_MD_size(kdf_md) * 255) {
# 		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_KEM_KEY_LENGTH)
# 		return 0
# 	}
#
# 	if (not (group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
# 		 or  not (Ppube = EC_POINT_new(group))
# 		 or  not (C = EC_POINT_new(group))
# 		 or  not (md_ctx = EVP_MD_CTX_new())
# 		 or  not (bn_ctx = BN_CTX_new())) {
# 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE)
# 		goto end
# 	}
# 	BN_CTX_start(bn_ctx)
# 	if (not (r = BN_CTX_get(bn_ctx))  or  not fp12_init(w, bn_ctx)) {
# 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE)
# 		goto end
# 	}
#
# 	/* parse Ppube */
# 	if (not EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(mpk->pointPpub),
# 		ASN1_STRING_length(mpk->pointPpub), bn_ctx)) {
# 		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB)
# 		goto end
# 	}
#
# 	# /* g = e(Ppube, P2) */
# 	if (not rate_pairing(w, NULL, Ppube, bn_ctx)) {
# 		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_RATE_PAIRING_ERROR)
# 		goto end
# 	}
#
# 	switch (OBJ_obj2nid(mpk->hash1)) {
# 	case NID_sm9hash1_with_sm3:
# 		hash1_md = EVP_sm3()
# 		break
# 	case NID_sm9hash1_with_sha256:
# 		hash1_md = EVP_sha256()
# 		break
# 	default:
# 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_SM9_LIB)
# 		goto end
# 	}
#
# 	/* parse Q_B = H1(ID_B or hid) * P1 + Ppube */
# 	// we should check mpk->hash1
# 	if (not SM9_hash1(hash1_md, &h, id, idlen, SM9_HID_ENC, n, bn_ctx)
# 		 or  not EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)
# 		 or  not EC_POINT_add(group, C, C, Ppube, bn_ctx)) {
# 		ERR_print_errors_fp(stderr)
# 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB)
# 		goto end
# 	}
#
# 	do {
# 		unsigned char *out = key
# 		size_t outlen = keylen
# 		unsigned char counter[4] = {0, 0, 0, 1}
# 		unsigned int len
#
# 		# /* r = rand([1, n-1]) */
# 		do {
# 			if (not BN_rand_range(r, n)) {
# 				goto end
# 			}
# 		} while (BN_is_zero(r))
#
# 		# /* C = r * Q_B */
# 		if (not EC_POINT_mul(group, C, NULL, C, r, bn_ctx)
# 			 or  EC_POINT_point2oct(group, C, POINT_CONVERSION_UNCOMPRESSED,
# 				cbuf, sizeof(cbuf), bn_ctx) not = sizeof(cbuf)) {
# 			SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB)
# 			goto end
# 		}
#
# 		# /* w = g^r */
# 		if (not fp12_pow(w, w, r, p, bn_ctx)  or  not fp12_to_bin(w, wbuf)) {
# 			SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_EXTENSION_FIELD_ERROR)
# 			goto end
# 		}
#
# 		/* K = KDF(C or w or ID_B, klen) */
# 		while (outlen > 0) {
# 			if (not EVP_DigestInit_ex(md_ctx, kdf_md, NULL)
# 				 or  not EVP_DigestUpdate(md_ctx, cbuf + 1, sizeof(cbuf) - 1)
# 				 or  not EVP_DigestUpdate(md_ctx, wbuf, sizeof(wbuf))
# 				 or  not EVP_DigestUpdate(md_ctx, id, idlen)
# 				 or  not EVP_DigestUpdate(md_ctx, counter, sizeof(counter))
# 				 or  not EVP_DigestFinal_ex(md_ctx, dgst, &len)) {
# 				SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EVP_LIB)
# 				goto end
# 			}
#
# 			if (len > outlen)
# 				len = outlen
# 			memcpy(out, dgst, len)
#
# 			out += len
# 			outlen -= len
# 			counter[3]++
# 		}
#
# 		all = 0
# 		len = 0
# 		while len < keylen:
# 			all |= key[len]
# 			len += 1
#
#
# 	} while (all == 0)
#
# 	memcpy(enced_key, cbuf, sizeof(cbuf))
# 	*enced_len = sizeof(cbuf)
#
#
# 	ret = 1
#
# end:
# 	EC_GROUP_free(group)
# 	EC_POINT_free(Ppube)
# 	EC_POINT_free(C)
# 	EVP_MD_CTX_free(md_ctx)
# 	if (bn_ctx) {
# 		BN_CTX_end(bn_ctx)
# 	}
# 	BN_free(r)
# 	BN_free(h)
# 	BN_CTX_free(bn_ctx)
# 	OPENSSL_cleanse(cbuf, sizeof(cbuf))
# 	OPENSSL_cleanse(wbuf, sizeof(wbuf))
# 	OPENSSL_cleanse(dgst, sizeof(dgst))
# 	return ret
# }
#
# int SM9_MASTER_KEY_ciphertext_size(const SM9_MASTER_KEY *master, size_t len)
# {
#
# }
#
# int SM9_encrypt(int type,
# 	const unsigned char *in, size_t inlen,
# 	unsigned char *out, size_t *outlen,
# 	SM9PublicParameters *mpk, const char *id, size_t idlen)
# {
# 	int ret = 0
# 	SM9Ciphertext *sm9cipher = NULL
# 	int kdf
# 	const EVP_MD *md
# 	unsigned char *key = NULL
# 	size_t keylen
# 	unsigned char C1[1 + 64]
# 	size_t C1_len
# 	unsigned char mac[EVP_MAX_MD_SIZE]
# 	unsigned int maclen = sizeof(mac)
# 	int len, i
#
# 	# /* parse type */
# 	switch (type) {
# 	case NID_sm9encrypt_with_sm3_xor:
# 		kdf = NID_sm9kdf_with_sm3
# 		md = EVP_sm3()
# 		break
# 	/*
# 	case NID_sm9encrypt_with_sha256_xor:
# 		kdf = NID_sm9kdf_with_sha256
# 		md = EVP_sha256()
# 		break
# 	*/
# 	case NID_sm9encrypt_with_sm3_sms4_cbc:
# 	case NID_sm9encrypt_with_sm3_sms4_ctr:
# 	default:
# 		return 0
# 	}
#
# 	keylen = inlen + EVP_MD_size(md)
#
# 	/* malloc */
# 	if (not (sm9cipher = SM9Ciphertext_new())
# 		 or  not (key = OPENSSL_malloc(keylen))) {
# 		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_MALLOC_FAILURE)
# 		goto end
# 	}
#
# 	/* C1 */
# 	if (not SM9_wrap_key(kdf, key, keylen, C1, &C1_len, mpk, id, idlen)) {
# 		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
#
# 	/* C2 = M xor K1 */
# 	for (i = 0 i < inlen i++) {
# 		key[i] ^= in[i]
# 	}
#
# 	/* C3 = Hv(C2 or K2) */
# 	if (not EVP_Digest(key, keylen, mac, &maclen, md, NULL)) {
# 		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_EVP_LIB)
# 		goto end
# 	}
#
# 	/* compose SM9Ciphertext */
# 	if (not ASN1_STRING_set(sm9cipher->pointC1, C1, C1_len)
# 		 or  not ASN1_STRING_set(sm9cipher->c2, key, inlen)
# 		 or  not ASN1_STRING_set(sm9cipher->c3, mac, maclen)) {
# 		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
#
# 	/* encode sm9 ciphertext */
# 	if ((len = i2d_SM9Ciphertext(sm9cipher, &out)) <= 0) {
# 		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
# 	*outlen = len
#
# 	ret = 1
#
# end:
# 	OPENSSL_free(sm9cipher)
# 	OPENSSL_clear_free(key, keylen)
# 	return ret
# }
#
# def SM9_decrypt(_type,inp,out, sk):
# 	ret = 0
#
# 	mac = [0] * EVP_MAX_MD_SIZE
# 	maclen = EVP_MAX_MD_SIZE
#
#
# 	# /* parse type */
# 	if _type=='NID_sm9encrypt_with_sm3_xor':
# 		# kdf = NID_sm9kdf_with_sm3
# 		# md = EVP_sm3()
# 		# break
# 		pass
#
# 	elif _type == 'NID_sm9encrypt_with_sm3_sms4_cbc':
# 		return None
# 	elif _type == 'ID_sm9encrypt_with_sm3_sms4_ctr':
# 		return None
# 	else:
# 		return None
#
# 	if (not in  or  not outlen  or  not sk) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_PASSED_NULL_PARAMETER)
# 		goto end
# 	}
#
# 	/* decode sm9 ciphertext */
# 	if (not (sm9cipher = d2i_SM9Ciphertext(NULL, &in, inlen))) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
# 	C2 = ASN1_STRING_get0_data(sm9cipher->c2)
# 	C2_len = ASN1_STRING_length(sm9cipher->c2)
#
# 	# /* check/return output length */
# 	if (not out) {
# 		*outlen = C2_len
# 		ret = 1
# 		goto end
# 	} else if (*outlen < C2_len) {
# 		SM9err(SM9_F_SM9_DECRYPT, SM9_R_BUFFER_TOO_SMALL)
# 		goto end
# 	}
#
# 	# /* unwrap key */
# 	keylen = C2_len + EVP_MD_size(md)
# 	if (not (key = OPENSSL_malloc(keylen))) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_MALLOC_FAILURE)
# 		goto end
# 	}
# 	if (not SM9_unwrap_key(kdf, key, keylen,
# 		ASN1_STRING_get0_data(sm9cipher->pointC1),
# 		ASN1_STRING_length(sm9cipher->pointC1), sk)) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
#
# 	/* M = C2 xor key */
# 	for (i = 0 i < C2_len i++) {
# 		out[i] = C2[i] ^ key[i]
# 	}
# 	*outlen = C2_len
#
# 	/* check mac length */
# 	if (ASN1_STRING_length(sm9cipher->c3) not = EVP_MD_size(md)) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB)
# 		goto end
# 	}
#
# 	# /* C3 = Hv(C2 or K2) */
#
# 	memcpy(key, C2, C2_len)
# 	if (not EVP_Digest(key, keylen, mac, &maclen, md, NULL)) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_EVP_LIB)
# 		goto end
# 	}
#
# 	if (CRYPTO_memcmp(ASN1_STRING_get0_data(sm9cipher->c3), mac, maclen) not = 0) {
# 		SM9err(SM9_F_SM9_DECRYPT, ERR_R_EVP_LIB)
# 		goto end
# 	}
#
# 	ret = 1
#
# 	return ret
#
#
#
#
# if __name__ == '__main__':
#     pass

from random import choice, choices, randrange

hex_list = '0123456789abcdef'
start_list = '123456789abcdef'
end_list = '13579bdf'


def generate_prime(length, n=100):
    while 1:
        check = ''.join(choices(hex_list, k=length-2))
        check = choice(start_list) + check + choice(end_list)
        t = n
        p = int(check, 16)
        while t >= 0:
            a = randrange(2,p)
            if pow(a, (p - 1), p) == 1:
                t -= 1
            else:
                break
        if t < 0:
            return p


if __name__ == '__main__':
    a = generate_prime(10)
    print(a)
