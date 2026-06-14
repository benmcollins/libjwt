/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-gnutls.h"

#define GCM_TAG_LEN 16

/* @rfc{7516,5.1} CSPRNG for CEK/IV generation. Backed by GnuTLS gnutls_rnd. */
int gnutls_rng(unsigned char *out, size_t len)
{
	if (out == NULL || len == 0)
		return 1; // LCOV_EXCL_LINE

	if (gnutls_rnd(GNUTLS_RND_KEY, out, len) != 0)
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* Map a GCM enc to the GnuTLS cipher algorithm. */
static gnutls_cipher_algorithm_t gcm_cipher(jwe_enc_t enc)
{
	switch (enc) {
	case JWE_ENC_A128GCM:
		return GNUTLS_CIPHER_AES_128_GCM;
	case JWE_ENC_A192GCM:
		return GNUTLS_CIPHER_AES_192_GCM;
	case JWE_ENC_A256GCM:
		return GNUTLS_CIPHER_AES_256_GCM;
	// LCOV_EXCL_START
	default:
		return GNUTLS_CIPHER_NULL;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.3} AES GCM content encryption. GnuTLS's one-shot AEAD appends
 * the tag to the ciphertext; we split it back out into separate JWE parts. */
int gnutls_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	gnutls_cipher_algorithm_t alg = gcm_cipher(enc);
	gnutls_aead_cipher_hd_t hd = NULL;
	gnutls_datum_t key;
	unsigned char *buf = NULL, *t = NULL;
	size_t outlen;
	int ret = 1;

	if (alg == GNUTLS_CIPHER_NULL || cek_len != jwe_enc_cek_len(enc))
		return 1; // LCOV_EXCL_LINE

	key.data = (unsigned char *)cek;
	key.size = (unsigned int)cek_len;

	if (gnutls_aead_cipher_init(&hd, alg, &key) != 0)
		return 1; // LCOV_EXCL_LINE

	/* AEAD output is plaintext length plus the tag. */
	outlen = pt_len + GCM_TAG_LEN;
	buf = jwt_malloc(outlen);
	t = jwt_malloc(GCM_TAG_LEN);
	if (buf == NULL || t == NULL)
		goto out; // LCOV_EXCL_LINE

	if (gnutls_aead_cipher_encrypt(hd, iv, iv_len, aad, aad_len,
				       GCM_TAG_LEN, pt, pt_len,
				       buf, &outlen) != 0)
		goto out; // LCOV_EXCL_LINE

	/* outlen now == pt_len + GCM_TAG_LEN; tag is the trailing bytes. */
	*ct_len = outlen - GCM_TAG_LEN;
	memcpy(t, buf + *ct_len, GCM_TAG_LEN);

	*ct = buf;
	*tag = t;
	*tag_len = GCM_TAG_LEN;
	buf = NULL;
	t = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	jwt_freemem(t);
	gnutls_aead_cipher_deinit(hd);

	return ret;
}

/* @rfc{7518,5.3} AES GCM content decryption with tag verification. We
 * recombine the separate JWE ciphertext and tag into the buffer GnuTLS's
 * one-shot AEAD expects (ciphertext || tag). */
int gnutls_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	gnutls_cipher_algorithm_t alg = gcm_cipher(enc);
	gnutls_aead_cipher_hd_t hd = NULL;
	gnutls_datum_t key;
	unsigned char *inbuf = NULL, *out = NULL;
	size_t inlen, outlen;
	int ret = 1;

	if (alg == GNUTLS_CIPHER_NULL || cek_len != jwe_enc_cek_len(enc) ||
	    tag_len != GCM_TAG_LEN)
		return 1; // LCOV_EXCL_LINE

	key.data = (unsigned char *)cek;
	key.size = (unsigned int)cek_len;

	if (gnutls_aead_cipher_init(&hd, alg, &key) != 0)
		return 1; // LCOV_EXCL_LINE

	inlen = ct_len + tag_len;
	inbuf = jwt_malloc(inlen);
	out = jwt_malloc(ct_len ? ct_len : 1);
	if (inbuf == NULL || out == NULL)
		goto out; // LCOV_EXCL_LINE

	memcpy(inbuf, ct, ct_len);
	memcpy(inbuf + ct_len, tag, tag_len);

	outlen = ct_len;

	/* A non-zero return is an authentication failure (tampered ct/aad/iv/
	 * tag or wrong CEK), the GCM equivalent of the tag not verifying. */
	if (gnutls_aead_cipher_decrypt(hd, iv, iv_len, aad, aad_len,
				       GCM_TAG_LEN, inbuf, inlen,
				       out, &outlen) != 0)
		goto out;

	*pt = out;
	*pt_len = outlen;
	out = NULL;
	ret = 0;

out:
	jwt_freemem(inbuf);
	jwt_scrub_and_free(out, ct_len ? ct_len : 1);
	gnutls_aead_cipher_deinit(hd);

	return ret;
}

/* @rfc{7518,5.2} Map a CBC-HMAC enc to the GnuTLS AES-CBC cipher, HMAC
 * algorithm, and the (equal) key half-length / truncated tag length. */
static int cbc_params(jwe_enc_t enc, gnutls_cipher_algorithm_t *cipher,
		      gnutls_mac_algorithm_t *mac, size_t *half)
{
	switch (enc) {
	case JWE_ENC_A128CBC_HS256:
		*cipher = GNUTLS_CIPHER_AES_128_CBC;
		*mac = GNUTLS_MAC_SHA256;
		*half = 16;
		return 0;
	case JWE_ENC_A192CBC_HS384:
		*cipher = GNUTLS_CIPHER_AES_192_CBC;
		*mac = GNUTLS_MAC_SHA384;
		*half = 24;
		return 0;
	case JWE_ENC_A256CBC_HS512:
		*cipher = GNUTLS_CIPHER_AES_256_CBC;
		*mac = GNUTLS_MAC_SHA512;
		*half = 32;
		return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.2.2.1} HMAC over AAD || IV || CT || AL, truncated to @half. */
static int cbc_hmac_tag(gnutls_mac_algorithm_t mac,
			const unsigned char *mac_key, size_t half,
			const unsigned char *aad, size_t aad_len,
			const unsigned char *iv, size_t iv_len,
			const unsigned char *ct, size_t ct_len,
			unsigned char *out)
{
	unsigned char full[64]; /* max SHA-512 */
	unsigned char al[8];
	uint64_t aad_bits = (uint64_t)aad_len * 8;
	unsigned char *buf;
	size_t buf_len, off = 0;
	int i, ret = 1;

	for (i = 7; i >= 0; i--) {
		al[i] = (unsigned char)(aad_bits & 0xff);
		aad_bits >>= 8;
	}

	buf_len = aad_len + iv_len + ct_len + sizeof(al);
	buf = jwt_malloc(buf_len ? buf_len : 1);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE

	if (aad_len) { memcpy(buf + off, aad, aad_len); off += aad_len; }
	memcpy(buf + off, iv, iv_len); off += iv_len;
	if (ct_len) { memcpy(buf + off, ct, ct_len); off += ct_len; }
	memcpy(buf + off, al, sizeof(al));

	if (gnutls_hmac_fast(mac, mac_key, half, buf, buf_len, full) == 0) {
		memcpy(out, full, half);
		ret = 0;
	}

	jwt_freemem(buf);

	return ret;
}

/* AES-CBC encrypt (PKCS#7 padding) via the GnuTLS one-shot cipher API. */
static int cbc_encrypt(gnutls_cipher_algorithm_t cipher,
		       const unsigned char *enc_key, size_t key_len,
		       const unsigned char *iv, size_t iv_len,
		       const unsigned char *pt, size_t pt_len,
		       unsigned char **ct, size_t *ct_len)
{
	gnutls_cipher_hd_t hd = NULL;
	gnutls_datum_t key, ivd;
	unsigned char *buf;
	size_t bs = 16, padded, pad;
	int ret = 1;

	key.data = (unsigned char *)enc_key;
	key.size = (unsigned int)key_len;
	ivd.data = (unsigned char *)iv;
	ivd.size = (unsigned int)iv_len;

	/* PKCS#7: always add 1..bs padding bytes. */
	pad = bs - (pt_len % bs);
	padded = pt_len + pad;

	buf = jwt_malloc(padded);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE
	if (pt_len)
		memcpy(buf, pt, pt_len);
	memset(buf + pt_len, (int)pad, pad);

	if (gnutls_cipher_init(&hd, cipher, &key, &ivd) != 0)
		goto out; // LCOV_EXCL_LINE
	if (gnutls_cipher_encrypt(hd, buf, padded) != 0)
		goto out; // LCOV_EXCL_LINE

	*ct = buf;
	*ct_len = padded;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	gnutls_cipher_deinit(hd);

	return ret;
}

/* AES-CBC decrypt + PKCS#7 unpad. */
static int cbc_decrypt(gnutls_cipher_algorithm_t cipher,
		       const unsigned char *enc_key, size_t key_len,
		       const unsigned char *iv, size_t iv_len,
		       const unsigned char *ct, size_t ct_len,
		       unsigned char **pt, size_t *pt_len)
{
	gnutls_cipher_hd_t hd = NULL;
	gnutls_datum_t key, ivd;
	unsigned char *buf;
	size_t bs = 16, pad;
	int ret = 1;

	if (ct_len == 0 || (ct_len % bs) != 0)
		return 1; // LCOV_EXCL_LINE

	key.data = (unsigned char *)enc_key;
	key.size = (unsigned int)key_len;
	ivd.data = (unsigned char *)iv;
	ivd.size = (unsigned int)iv_len;

	buf = jwt_malloc(ct_len);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE
	memcpy(buf, ct, ct_len);

	if (gnutls_cipher_init(&hd, cipher, &key, &ivd) != 0)
		goto out; // LCOV_EXCL_LINE
	if (gnutls_cipher_decrypt(hd, buf, ct_len) != 0)
		goto out; // LCOV_EXCL_LINE

	/* Strip and validate PKCS#7 padding. The HMAC tag is verified before
	 * this is reached, so a corrupt-padding path is not reachable with a
	 * valid tag; the check stays as defense in depth. */
	pad = buf[ct_len - 1];
	if (pad == 0 || pad > bs || pad > ct_len)
		goto out; // LCOV_EXCL_LINE

	*pt = buf;
	*pt_len = ct_len - pad;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, ct_len);
	gnutls_cipher_deinit(hd);

	return ret;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content encryption (encrypt-then-MAC). */
int gnutls_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	unsigned char hmac[64], *t = NULL;
	const unsigned char *mac_key, *enc_key;
	size_t half;

	if (cbc_params(enc, &cipher, &mac, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16)
		return 1; // LCOV_EXCL_LINE

	mac_key = cek;
	enc_key = cek + half;

	if (cbc_encrypt(cipher, enc_key, half, iv, iv_len, pt, pt_len,
			ct, ct_len))
		return 1; // LCOV_EXCL_LINE

	if (cbc_hmac_tag(mac, mac_key, half, aad, aad_len, iv, iv_len,
			 *ct, *ct_len, hmac)) {
		// LCOV_EXCL_START
		jwt_freemem(*ct);
		return 1;
		// LCOV_EXCL_STOP
	}

	t = jwt_malloc(half);
	if (t == NULL) {
		// LCOV_EXCL_START
		jwt_freemem(*ct);
		return 1;
		// LCOV_EXCL_STOP
	}
	memcpy(t, hmac, half);

	*tag = t;
	*tag_len = half;

	return 0;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content decryption with constant-time tag
 * verification before decryption. */
int gnutls_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	unsigned char hmac[64];
	const unsigned char *mac_key, *enc_key;
	size_t half;

	if (cbc_params(enc, &cipher, &mac, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16 || tag_len != half)
		return 1; // LCOV_EXCL_LINE

	mac_key = cek;
	enc_key = cek + half;

	/* @rfc{7518,5.2.2.2} Verify the tag in constant time first. */
	if (cbc_hmac_tag(mac, mac_key, half, aad, aad_len, iv, iv_len,
			 ct, ct_len, hmac))
		return 1; // LCOV_EXCL_LINE
	if (gnutls_memcmp(hmac, tag, half) != 0)
		return 1;

	if (cbc_decrypt(cipher, enc_key, half, iv, iv_len, ct, ct_len,
			pt, pt_len))
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* RFC 3394 AES Key Wrap. GnuTLS exposes no AES-ECB or key-wrap primitive, so
 * we build the single-block AES operation each step needs from AES-CBC with a
 * zero IV: CBC of one 16-byte block with IV=0 is identical to ECB of that
 * block. A fresh context (hence a fresh zero IV) is used per block. */
static gnutls_cipher_algorithm_t kw_cbc(size_t kek_len)
{
	switch (kek_len) {
	case 16:
		return GNUTLS_CIPHER_AES_128_CBC;
	case 24:
		return GNUTLS_CIPHER_AES_192_CBC;
	case 32:
		return GNUTLS_CIPHER_AES_256_CBC;
	// LCOV_EXCL_START
	default:
		return GNUTLS_CIPHER_NULL;
	// LCOV_EXCL_STOP
	}
}

static const unsigned char KW_IV[8] =
	{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

/* One AES block (16 bytes) in place, via AES-CBC with a zero IV. */
static int kw_aes_block(gnutls_cipher_algorithm_t alg, const gnutls_datum_t *key,
			int encrypt, unsigned char *block)
{
	gnutls_cipher_hd_t hd = NULL;
	unsigned char zero_iv[16] = { 0 };
	gnutls_datum_t ivd = { zero_iv, sizeof(zero_iv) };
	int ret;

	if (gnutls_cipher_init(&hd, alg, key, &ivd) != 0)
		return 1; // LCOV_EXCL_LINE

	if (encrypt)
		ret = gnutls_cipher_encrypt(hd, block, 16);
	else
		ret = gnutls_cipher_decrypt(hd, block, 16);

	gnutls_cipher_deinit(hd);

	return ret ? 1 : 0;
}

/* @rfc{7518,4.4} AES Key Wrap (RFC 3394 section 2.2.1) with a raw KEK. */
static int kw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *cek, size_t cek_len,
		       unsigned char **out, size_t *out_len)
{
	size_t n, i, j;
	gnutls_cipher_algorithm_t alg;
	gnutls_datum_t keyd;
	unsigned char *r = NULL, a[8], block[16];
	uint64_t t;
	int ret = 1;

	alg = kw_cbc(kek_len);
	if (alg == GNUTLS_CIPHER_NULL || cek_len < 16 || (cek_len % 8) != 0)
		return 1; // LCOV_EXCL_LINE

	n = cek_len / 8;
	keyd.data = (unsigned char *)kek;
	keyd.size = (unsigned int)kek_len;

	/* Set A = IV, R = plaintext. */
	memcpy(a, KW_IV, 8);
	r = jwt_malloc(cek_len);
	if (r == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(r, cek, cek_len);

	for (j = 0; j < 6; j++) {
		for (i = 0; i < n; i++) {
			memcpy(block, a, 8);
			memcpy(block + 8, r + i * 8, 8);
			if (kw_aes_block(alg, &keyd, 1, block))
				goto out; // LCOV_EXCL_LINE
			/* A = MSB(64, B) ^ t, where t = (n*j)+i+1 */
			t = (uint64_t)(n * j) + i + 1;
			memcpy(a, block, 8);
			a[7] ^= (unsigned char)(t & 0xff);
			a[6] ^= (unsigned char)((t >> 8) & 0xff);
			a[5] ^= (unsigned char)((t >> 16) & 0xff);
			a[4] ^= (unsigned char)((t >> 24) & 0xff);
			memcpy(r + i * 8, block + 8, 8);
		}
	}

	*out = jwt_malloc(cek_len + 8);
	if (*out == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(*out, a, 8);
	memcpy(*out + 8, r, cek_len);
	*out_len = cek_len + 8;
	ret = 0;

out:
	jwt_scrub_and_free(r, cek_len);

	return ret;
}

/* @rfc{7518,4.4} AES Key Unwrap (RFC 3394 section 2.2.2) with a raw KEK,
 * including the integrity check on the recovered A6 IV. */
static int kw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **cek, size_t *cek_len)
{
	size_t n, i, plen;
	long j;
	gnutls_cipher_algorithm_t alg;
	gnutls_datum_t keyd;
	unsigned char *r = NULL, a[8], block[16];
	uint64_t t;
	int ret = 1;

	alg = kw_cbc(kek_len);
	if (alg == GNUTLS_CIPHER_NULL || in_len < 24 || (in_len % 8) != 0)
		return 1;

	plen = in_len - 8;
	n = plen / 8;
	keyd.data = (unsigned char *)kek;
	keyd.size = (unsigned int)kek_len;

	memcpy(a, in, 8);
	r = jwt_malloc(plen);
	if (r == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(r, in + 8, plen);

	for (j = 5; j >= 0; j--) {
		for (i = n; i >= 1; i--) {
			t = (uint64_t)(n * (size_t)j) + i;
			memcpy(block, a, 8);
			block[7] ^= (unsigned char)(t & 0xff);
			block[6] ^= (unsigned char)((t >> 8) & 0xff);
			block[5] ^= (unsigned char)((t >> 16) & 0xff);
			block[4] ^= (unsigned char)((t >> 24) & 0xff);
			memcpy(block + 8, r + (i - 1) * 8, 8);
			if (kw_aes_block(alg, &keyd, 0, block))
				goto out; // LCOV_EXCL_LINE
			memcpy(a, block, 8);
			memcpy(r + (i - 1) * 8, block + 8, 8);
		}
	}

	/* Integrity: the recovered A must equal the RFC 3394 default IV. */
	if (gnutls_memcmp(a, KW_IV, 8) != 0)
		goto out;

	*cek = jwt_malloc(plen);
	if (*cek == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(*cek, r, plen);
	*cek_len = plen;
	ret = 0;

out:
	jwt_scrub_and_free(r, plen);

	return ret;
}

/* AES Key Wrap / Unwrap with the recipient's oct key (JWK). */
int gnutls_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
		       size_t cek_len, unsigned char **out, size_t *out_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

int gnutls_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
			 size_t in_len, unsigned char **cek, size_t *cek_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
}

/* AES Key Wrap / Unwrap with a raw KEK (ECDH-ES+A*KW agreed key). */
int gnutls_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			   const unsigned char *cek, size_t cek_len,
			   unsigned char **out, size_t *out_len)
{
	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

int gnutls_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			     const unsigned char *in, size_t in_len,
			     unsigned char **cek, size_t *cek_len)
{
	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
}
