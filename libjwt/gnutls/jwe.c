/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
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

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

/* ============== RSA-OAEP (RFC 7518 4.3), GnuTLS >= 3.8.4 ============== */

/* The OAEP digest for the alg. RSA-OAEP-256 uses SHA-256. RSA-OAEP uses SHA-1,
 * which GnuTLS/nettle's OAEP does NOT implement (its OAEP accepts only SHA-256/
 * 384/512); that alg is handled via the OpenSSL fallback below. In GnuTLS the
 * SPKI OAEP digest also drives MGF1, matching the JWE requirement. */
static gnutls_digest_algorithm_t oaep_dig(jwe_key_alg_t alg)
{
	if (alg == JWE_ALG_RSA_OAEP_256)
		return GNUTLS_DIG_SHA256;

	/* RSA-OAEP (SHA-1) is not GnuTLS-native; signalled to the caller. */
	return GNUTLS_DIG_UNKNOWN;
}

/* @rfc{7518,4.3} RSAES-OAEP encryption of the CEK to the recipient public key.
 *
 * RSA-OAEP-256 is native: set the OAEP SPKI (SHA-256) directly on the
 * raw-imported pubkey and encrypt — no usage flags or key round-trips needed.
 * RSA-OAEP (SHA-1) is unsupported by GnuTLS/nettle, so it falls back to OpenSSL
 * via the JWK's PEM. */
int gnutls_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			   const unsigned char *cek, size_t cek_len,
			   unsigned char **out, size_t *out_len)
{
	const gnutls_jwk_t *jk = key->provider_data;
	gnutls_digest_algorithm_t dig = oaep_dig(alg);
	gnutls_x509_spki_t spki = NULL;
	gnutls_pubkey_t pub = NULL;
	gnutls_datum_t der = { NULL, 0 }, pt, ct = { NULL, 0 };
	unsigned char *buf = NULL;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA)
		return 1; // LCOV_EXCL_LINE

	/* SHA-1 RSA-OAEP: GnuTLS/nettle has no SHA-1 OAEP. */
	if (dig == GNUTLS_DIG_UNKNOWN) {
#ifdef HAVE_OPENSSL
		/* Delegate to OpenSSL via the PEM when that backend is present. */
		return openssl_encrypt_cek_rsa_pem(alg, jwks_item_pem(key), cek,
						   cek_len, out, out_len);
#else
		/* No OpenSSL backend: RSA-OAEP (SHA-1) is not supported here. */
		return 1;
#endif
	}

	if (gnutls_x509_spki_init(&spki))
		return 1; // LCOV_EXCL_LINE
	if (gnutls_pubkey_init(&pub))
		goto out; // LCOV_EXCL_LINE

	/* Work on a private copy so the SPKI override doesn't mutate the JWK's
	 * stored handle. */
	if (gnutls_pubkey_export2(jk->pub, GNUTLS_X509_FMT_DER, &der) ||
	    gnutls_pubkey_import(pub, &der, GNUTLS_X509_FMT_DER))
		goto out; // LCOV_EXCL_LINE

	if (gnutls_x509_spki_set_rsa_oaep_params(spki, dig, NULL) ||
	    gnutls_pubkey_set_spki(pub, spki, 0))
		goto out; // LCOV_EXCL_LINE

	pt.data = (unsigned char *)cek;
	pt.size = (unsigned int)cek_len;

	if (gnutls_pubkey_encrypt_data(pub, 0, &pt, &ct))
		goto out; // LCOV_EXCL_LINE

	buf = jwt_malloc(ct.size);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(buf, ct.data, ct.size);

	*out = buf;
	*out_len = ct.size;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	if (der.data)
		gnutls_free(der.data);
	gnutls_free(ct.data);
	if (pub)
		gnutls_pubkey_deinit(pub);
	gnutls_x509_spki_deinit(spki);

	return ret;
}

/* @rfc{7518,4.3} RSAES-OAEP decryption of the JWE Encrypted Key. A failure
 * here is funnelled by the caller into the uniform random-CEK path (11.5).
 *
 * RSA-OAEP-256 is native: set the OAEP SPKI (SHA-256) directly on the
 * raw-imported privkey and decrypt. RSA-OAEP (SHA-1) falls back to OpenSSL. */
int gnutls_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			   const unsigned char *in, size_t in_len,
			   unsigned char **cek, size_t *cek_len)
{
	const gnutls_jwk_t *jk = key->provider_data;
	gnutls_datum_t ct, pt = { NULL, 0 };
	unsigned char *buf = NULL;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA || jk->priv == NULL)
		return 1; // LCOV_EXCL_LINE

	/* SHA-1 RSA-OAEP: GnuTLS/nettle has no SHA-1 OAEP. */
	if (oaep_dig(alg) == GNUTLS_DIG_UNKNOWN) {
#ifdef HAVE_OPENSSL
		/* Delegate to OpenSSL via the PEM when that backend is present. */
		return openssl_decrypt_cek_rsa_pem(alg, jwks_item_pem(key), in,
						   in_len, cek, cek_len);
#else
		/* No OpenSSL backend: RSA-OAEP (SHA-1) is not supported here. */
		return 1;
#endif
	}

	/* The RSA-OAEP-256 SPKI was attached to jk->priv once at parse time
	 * (gnutls_jwk_rsa_set_oaep), so decrypt does not mutate the shared key
	 * here — keeping concurrent decrypts with one key race-free. */
	ct.data = (unsigned char *)in;
	ct.size = (unsigned int)in_len;

	/* A decryption/padding failure returns non-zero here. */
	if (gnutls_privkey_decrypt_data(jk->priv, 0, &ct, &pt))
		goto out;

	buf = jwt_malloc(pt.size ? pt.size : 1);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE
	memcpy(buf, pt.data, pt.size);

	*cek = buf;
	*cek_len = pt.size;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	if (pt.data) {
		/* Scrub the recovered CEK before releasing the GnuTLS buffer. */
		gnutls_memset(pt.data, 0, pt.size);
		gnutls_free(pt.data);
	}

	return ret;
}

/* ================== ECDH-ES (RFC 7518 4.6), GnuTLS >= 3.8.2 ================== */

/* The derived-key length (octets) and ASCII AlgorithmID for the Concat KDF
 * (Direct: enc/CEK-len; +A*KW: alg/AES-KW size). */
static int ecdh_keydatalen(jwe_key_alg_t alg, jwe_enc_t enc,
			   size_t *len, const char **algid)
{
	switch (alg) {
	case JWE_ALG_ECDH_ES:
		*len = jwe_enc_cek_len(enc);
		*algid = jwe_enc_str(enc);
		return (*len && *algid) ? 0 : 1;
	case JWE_ALG_ECDH_ES_A128KW:
		*len = 16; *algid = jwe_alg_str(alg); return 0;
	case JWE_ALG_ECDH_ES_A192KW:
		*len = 24; *algid = jwe_alg_str(alg); return 0;
	case JWE_ALG_ECDH_ES_A256KW:
		*len = 32; *algid = jwe_alg_str(alg); return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* Append a length-prefixed (32-bit big-endian) datum to a buffer. */
static void concat_put_data(unsigned char *buf, size_t *off,
			    const unsigned char *data, size_t len)
{
	buf[(*off)++] = (unsigned char)((len >> 24) & 0xff);
	buf[(*off)++] = (unsigned char)((len >> 16) & 0xff);
	buf[(*off)++] = (unsigned char)((len >> 8) & 0xff);
	buf[(*off)++] = (unsigned char)(len & 0xff);
	if (len) {
		memcpy(buf + *off, data, len);
		*off += len;
	}
}

/* @rfc{7518,4.6.2} Concat KDF (SHA-256, single round; JWE needs <= 32 bytes). */
static int concat_kdf(const unsigned char *z, size_t z_len, const char *algid,
		      const unsigned char *apu, size_t apu_len,
		      const unsigned char *apv, size_t apv_len,
		      size_t keydatalen, unsigned char *out)
{
	unsigned char hash[32];
	unsigned char *buf;
	size_t algid_len = strlen(algid);
	size_t buf_len, off = 0;
	uint32_t bits = (uint32_t)(keydatalen * 8);
	unsigned char counter[4] = { 0, 0, 0, 1 };
	unsigned char supppub[4];
	int ret = 1;

	if (keydatalen > sizeof(hash))
		return 1; // LCOV_EXCL_LINE

	supppub[0] = (unsigned char)((bits >> 24) & 0xff);
	supppub[1] = (unsigned char)((bits >> 16) & 0xff);
	supppub[2] = (unsigned char)((bits >> 8) & 0xff);
	supppub[3] = (unsigned char)(bits & 0xff);

	buf_len = 4 + z_len + (4 + algid_len) + (4 + apu_len) + (4 + apv_len) + 4;
	buf = jwt_malloc(buf_len);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE

	memcpy(buf + off, counter, 4); off += 4;
	memcpy(buf + off, z, z_len); off += z_len;
	concat_put_data(buf, &off, (const unsigned char *)algid, algid_len);
	concat_put_data(buf, &off, apu, apu_len);
	concat_put_data(buf, &off, apv, apv_len);
	memcpy(buf + off, supppub, 4); off += 4;

	if (gnutls_hash_fast(GNUTLS_DIG_SHA256, buf, off, hash) == 0) {
		memcpy(out, hash, keydatalen);
		ret = 0;
	}

	jwt_scrub_and_free(buf, buf_len);

	return ret;
}

/* Is this an OKP X-curve? */
static int crv_is_okp_x(const char *crv)
{
	return !strcmp(crv, "X25519") || !strcmp(crv, "X448");
}

/* NIST coordinate length (octets) for a curve, for fixed-width epk encoding. */
static size_t nist_fieldlen(const char *crv)
{
	if (!strcmp(crv, "P-256"))
		return 32;
	if (!strcmp(crv, "P-384"))
		return 48;
	if (!strcmp(crv, "P-521"))
		return 66;
	return 0; // LCOV_EXCL_LINE
}

/* base64url-encode a coordinate normalized to exactly @fieldlen octets. GnuTLS
 * may return a coordinate either SHORTER than the field width (leading zero
 * bytes dropped, e.g. P-521 y as 65) or LONGER by one (a leading 0x00 sign/pad
 * byte, e.g. P-256 x as 33). JWE peers expect the fixed field width, so strip
 * leading zeros down to fieldlen and left-pad up to it. @fieldlen 0 means "use
 * the datum as-is" (OKP raw keys). */
static int encode_coord(char **b64, const gnutls_datum_t *d, size_t fieldlen)
{
	unsigned char buf[66];
	const unsigned char *data = d->data;
	size_t size = d->size;

	if (fieldlen == 0 || size == fieldlen)
		return jwt_base64uri_encode(b64, (char *)data, (int)size);

	/* Drop leading zero bytes if longer than the field width. */
	while (size > fieldlen && data[0] == 0) {
		data++;
		size--;
	}

	if (size > fieldlen || fieldlen > sizeof(buf))
		return -1; // LCOV_EXCL_LINE

	memset(buf, 0, fieldlen);
	memcpy(buf + (fieldlen - size), data, size);

	return jwt_base64uri_encode(b64, (char *)buf, (int)fieldlen);
}

/* Build an "epk" JWK object from an ephemeral public key. EC emits {x,y} with
 * fixed-width coordinates; OKP emits {x}. NIST coordinates are big-endian; the
 * OKP raw key is RFC 7748 little-endian — gnutls handles the OKP format. */
static jwt_json_t *epk_to_json(gnutls_pubkey_t eph, const char *crv, int is_okp)
{
	jwt_json_t *epk = NULL;
	char_auto *x_b64 = NULL, *y_b64 = NULL;
	gnutls_datum_t x = { NULL, 0 }, y = { NULL, 0 };
	size_t fieldlen = is_okp ? 0 : nist_fieldlen(crv);

	if (gnutls_pubkey_export_ecc_raw(eph, NULL, &x, is_okp ? NULL : &y))
		return NULL; // LCOV_EXCL_LINE

	if (encode_coord(&x_b64, &x, fieldlen) <= 0)
		goto out; // LCOV_EXCL_LINE
	if (!is_okp && encode_coord(&y_b64, &y, fieldlen) <= 0)
		goto out; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		goto out; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str(is_okp ? "OKP" : "EC"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));
	if (!is_okp)
		jwt_json_obj_set(epk, "y", jwt_json_create_str(y_b64));

out:
	gnutls_free(x.data);
	gnutls_free(y.data);

	return epk;
}

/* Build a peer public key from an "epk" JWK object. The crv must match. */
static int epk_from_json(jwt_json_t *epk, const char *want_crv,
			 gnutls_ecc_curve_t curve, int is_okp,
			 gnutls_pubkey_t *out)
{
	jwt_json_t *jkty, *jcrv, *jx, *jy;
	const char *kty, *crv;
	gnutls_datum_t x = { NULL, 0 }, y = { NULL, 0 };
	gnutls_pubkey_t pub = NULL;
	int xlen = 0, ylen = 0, ret = 1;

	jkty = jwt_json_obj_get(epk, "kty");
	jcrv = jwt_json_obj_get(epk, "crv");
	jx = jwt_json_obj_get(epk, "x");
	jy = jwt_json_obj_get(epk, "y");
	if (!jkty || !jcrv || !jx || !jwt_json_is_string(jkty) ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx) ||
	    (!is_okp && (!jy || !jwt_json_is_string(jy))))
		return 1; // LCOV_EXCL_LINE

	kty = jwt_json_str_val(jkty);
	crv = jwt_json_str_val(jcrv);
	if (strcmp(kty, is_okp ? "OKP" : "EC") || strcmp(crv, want_crv))
		return 1;

	x.data = jwt_base64uri_decode(jwt_json_str_val(jx), &xlen);
	if (x.data == NULL || xlen <= 0)
		goto out; // LCOV_EXCL_LINE
	x.size = (unsigned int)xlen;

	if (!is_okp) {
		y.data = jwt_base64uri_decode(jwt_json_str_val(jy), &ylen);
		if (y.data == NULL || ylen <= 0)
			goto out; // LCOV_EXCL_LINE
		y.size = (unsigned int)ylen;
	}

	if (gnutls_pubkey_init(&pub))
		goto out; // LCOV_EXCL_LINE
	if (gnutls_pubkey_import_ecc_raw(pub, curve, &x, is_okp ? NULL : &y)) {
		// LCOV_EXCL_START
		gnutls_pubkey_deinit(pub);
		goto out;
		// LCOV_EXCL_STOP
	}

	*out = pub;
	ret = 0;

out:
	jwt_freemem(x.data);
	jwt_freemem(y.data);

	return ret;
}

/* @rfc{7518,4.6} ECDH-ES key agreement using native GnuTLS. On encrypt an
 * ephemeral keypair is generated on the recipient's curve, "epk" is written to
 * @hdr, and the agreed key derived; on decrypt "epk" is read from @hdr. The raw
 * shared secret Z (gnutls_privkey_derive_secret, nonce=NULL) feeds the Concat
 * KDF. The derived key (CEK for ECDH-ES, KEK for +A*KW) is returned in @dk. */
int gnutls_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
		       const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
		       unsigned char **dk, size_t *dk_len)
{
	const gnutls_jwk_t *jk = key->provider_data;
	const char *crv = jwks_item_curve(key);
	gnutls_ecc_curve_t curve;
	gnutls_privkey_t eph = NULL;
	gnutls_pubkey_t eph_pub = NULL, peer = NULL;
	gnutls_datum_t z = { NULL, 0 };
	unsigned char *apu = NULL, *apv = NULL, *out = NULL;
	unsigned char *z_buf = NULL, zpad[66];
	size_t z_len = 0;
	int apu_len = 0, apv_len = 0, is_okp, ret = 1;
	size_t keydatalen = 0;
	const char *algid = NULL;
	jwt_json_t *japu, *japv, *jepk;

	if (jk == NULL || crv == NULL || crv[0] == '\0')
		return 1; // LCOV_EXCL_LINE

	is_okp = crv_is_okp_x(crv);
	curve = is_okp ? (!strcmp(crv, "X25519") ? GNUTLS_ECC_CURVE_X25519
						 : GNUTLS_ECC_CURVE_X448)
		       : (!strcmp(crv, "P-256") ? GNUTLS_ECC_CURVE_SECP256R1 :
			  !strcmp(crv, "P-384") ? GNUTLS_ECC_CURVE_SECP384R1 :
			  !strcmp(crv, "P-521") ? GNUTLS_ECC_CURVE_SECP521R1 :
						  GNUTLS_ECC_CURVE_INVALID);
	if (curve == GNUTLS_ECC_CURVE_INVALID)
		return 1; // LCOV_EXCL_LINE (callers gate the curve before deriving)

	if (ecdh_keydatalen(alg, enc, &keydatalen, &algid))
		return 1; // LCOV_EXCL_LINE

	out = jwt_malloc(keydatalen);
	if (out == NULL)
		return 1; // LCOV_EXCL_LINE

	if (for_encrypt) {
		gnutls_pk_algorithm_t pk = gnutls_ecc_curve_get_pk(curve);

		/* Ephemeral keypair on the recipient's curve. */
		if (gnutls_privkey_init(&eph) ||
		    gnutls_privkey_generate(eph, pk, GNUTLS_CURVE_TO_BITS(curve),
					    0))
			goto out; // LCOV_EXCL_LINE
		if (gnutls_pubkey_init(&eph_pub) ||
		    gnutls_pubkey_import_privkey(eph_pub, eph, 0, 0))
			goto out; // LCOV_EXCL_LINE

		/* Z = ECDH(eph_priv, recipient_pub). */
		if (gnutls_privkey_derive_secret(eph, jk->pub, NULL, &z, 0))
			goto out; // LCOV_EXCL_LINE

		jepk = epk_to_json(eph_pub, crv, is_okp);
		if (jepk == NULL)
			goto out; // LCOV_EXCL_LINE
		jwt_json_obj_set(hdr, "epk", jepk);
	} else {
		if (jk->priv == NULL)
			goto out; // LCOV_EXCL_LINE
		jepk = jwt_json_obj_get(hdr, "epk");
		if (jepk == NULL)
			goto out;
		if (epk_from_json(jepk, crv, curve, is_okp, &peer))
			goto out;
		/* Z = ECDH(recipient_priv, eph_pub). */
		if (gnutls_privkey_derive_secret(jk->priv, peer, NULL, &z, 0))
			goto out; // LCOV_EXCL_LINE
	}

	/* The Concat KDF consumes Z at the curve's fixed field width. GnuTLS may
	 * return a NIST Z either shorter (leading zeros dropped) or longer by one
	 * (a leading 0x00 byte) than the field; normalize to exactly the width in
	 * zpad (OpenSSL/MbedTLS always use the full width — required for
	 * cross-backend interop). OKP X-curve secrets are already fixed-width. */
	z_buf = z.data;
	z_len = z.size;
	if (!is_okp) {
		size_t fl = nist_fieldlen(crv);
		const unsigned char *zd = z.data;
		size_t zs = z.size;

		/* Only runs when GnuTLS returns an over-length NIST Z (a leading
		 * 0x00 byte); not reproducible deterministically from a test. */
		while (zs > fl && zd[0] == 0) {
			// LCOV_EXCL_START
			zd++;
			zs--;
			// LCOV_EXCL_STOP
		}
		if (fl && zs <= fl && fl <= sizeof(zpad)) {
			memset(zpad, 0, fl - zs);
			memcpy(zpad + (fl - zs), zd, zs);
			z_buf = zpad;
			z_len = fl;
		}
	}

	/* apu/apv (optional), fed to the Concat KDF as-is. */
	japu = jwt_json_obj_get(hdr, "apu");
	if (japu && jwt_json_is_string(japu))
		apu = jwt_base64uri_decode(jwt_json_str_val(japu), &apu_len);
	japv = jwt_json_obj_get(hdr, "apv");
	if (japv && jwt_json_is_string(japv))
		apv = jwt_base64uri_decode(jwt_json_str_val(japv), &apv_len);

	if (concat_kdf(z_buf, z_len, algid,
		       apu, apu_len < 0 ? 0 : (size_t)apu_len,
		       apv, apv_len < 0 ? 0 : (size_t)apv_len, keydatalen, out))
		goto out; // LCOV_EXCL_LINE

	*dk = out;
	*dk_len = keydatalen;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(out, keydatalen);
	jwt_freemem(apu);
	jwt_freemem(apv);
	gnutls_memset(zpad, 0, sizeof(zpad));
	if (z.data) {
		gnutls_memset(z.data, 0, z.size);
		gnutls_free(z.data);
	}
	if (eph)
		gnutls_privkey_deinit(eph);
	if (eph_pub)
		gnutls_pubkey_deinit(eph_pub);
	if (peer)
		gnutls_pubkey_deinit(peer);

	return ret;
}
