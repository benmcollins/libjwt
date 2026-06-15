/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-mbedtls.h"

#define GCM_TAG_LEN 16

/* Is this a GCM content encryption algorithm? (the dispatch in jwe.c already
 * routes by family, but the op double-checks its own input). */
static int enc_is_gcm(jwe_enc_t enc)
{
	return enc == JWE_ENC_A128GCM || enc == JWE_ENC_A192GCM ||
	       enc == JWE_ENC_A256GCM;
}

/* Import a raw symmetric key as a volatile PSA AES key with the given policy. */
static int import_aes_key(const unsigned char *key, size_t key_len,
			  psa_algorithm_t alg, psa_key_usage_t usage,
			  mbedtls_svc_key_id_t *kid)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st;

	*kid = MBEDTLS_SVC_KEY_ID_INIT;

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_algorithm(&attr, alg);

	st = psa_import_key(&attr, key, key_len, kid);
	psa_reset_key_attributes(&attr);

	return st != PSA_SUCCESS;
}

/* @rfc{7516,5.1} CSPRNG for CEK/IV generation and the @rfc{7516,11.5}
 * random-CEK fallback. Backed by the PSA RNG. */
int mbedtls_rng(unsigned char *out, size_t len)
{
	if (out == NULL || len == 0)
		return 1; // LCOV_EXCL_LINE

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	return psa_generate_random(out, len) != PSA_SUCCESS;
}

/* @rfc{7518,5.3} AES GCM content encryption. PSA returns ciphertext||tag, which
 * we split into the separate JWE fields. */
int mbedtls_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	unsigned char *buf = NULL, *ct_out = NULL, *tag_out = NULL;
	size_t buf_size, out_len = 0, ctl;
	int ret = 1;

	if (!enc_is_gcm(enc) || cek_len != jwe_enc_cek_len(enc))
		return 1; // LCOV_EXCL_LINE

	if (import_aes_key(cek, cek_len, PSA_ALG_GCM, PSA_KEY_USAGE_ENCRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	buf_size = PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM,
						pt_len);
	buf = jwt_malloc(buf_size);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (psa_aead_encrypt(kid, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
			     pt, pt_len, buf, buf_size, &out_len))
		goto out; // LCOV_EXCL_LINE
	if (out_len < GCM_TAG_LEN)
		goto out; // LCOV_EXCL_LINE

	ctl = out_len - GCM_TAG_LEN;

	ct_out = jwt_malloc(ctl ? ctl : 1);
	tag_out = jwt_malloc(GCM_TAG_LEN);
	if (ct_out == NULL || tag_out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (ctl)
		memcpy(ct_out, buf, ctl);
	memcpy(tag_out, buf + ctl, GCM_TAG_LEN);

	*ct = ct_out;
	*ct_len = ctl;
	*tag = tag_out;
	*tag_len = GCM_TAG_LEN;
	ct_out = NULL;
	tag_out = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	jwt_freemem(ct_out);
	jwt_freemem(tag_out);
	psa_destroy_key(kid);

	return ret;
}

/* @rfc{7518,5.3} AES GCM content decryption with tag verification. */
int mbedtls_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	unsigned char *in = NULL, *out = NULL;
	size_t in_len, out_size = 0, out_len = 0;
	int ret = 1;

	if (!enc_is_gcm(enc) || cek_len != jwe_enc_cek_len(enc) ||
	    tag_len != GCM_TAG_LEN)
		return 1; // LCOV_EXCL_LINE

	if (import_aes_key(cek, cek_len, PSA_ALG_GCM, PSA_KEY_USAGE_DECRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	/* PSA AEAD wants ciphertext||tag contiguous. */
	in_len = ct_len + tag_len;
	in = jwt_malloc(in_len);
	if (in == NULL)
		goto out; // LCOV_EXCL_LINE
	if (ct_len)
		memcpy(in, ct, ct_len);
	memcpy(in + ct_len, tag, tag_len);

	out_size = PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM,
						in_len);
	out = jwt_malloc(out_size ? out_size : 1);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	/* A non-zero return is the constant-time authentication failure. */
	if (psa_aead_decrypt(kid, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
			     in, in_len, out, out_size ? out_size : 1, &out_len))
		goto out;

	*pt = out;
	*pt_len = out_len;
	out = NULL;
	ret = 0;

out:
	jwt_freemem(in);
	jwt_scrub_and_free(out, out_size);
	psa_destroy_key(kid);

	return ret;
}

/* @rfc{7518,5.2} Map a CBC-HMAC enc to its HMAC digest and the (equal) MAC/ENC
 * key half-length, which is also the truncated tag length. */
static int cbc_params(jwe_enc_t enc, psa_algorithm_t *hash, size_t *half)
{
	switch (enc) {
	case JWE_ENC_A128CBC_HS256:
		*hash = PSA_ALG_SHA_256; *half = 16;
		return 0;
	case JWE_ENC_A192CBC_HS384:
		*hash = PSA_ALG_SHA_384; *half = 24;
		return 0;
	case JWE_ENC_A256CBC_HS512:
		*hash = PSA_ALG_SHA_512; *half = 32;
		return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.2.2.1} Assemble AAD || IV || CT || AL into a heap buffer, where AL
 * is the 64-bit big-endian bit length of the AAD. The caller frees it. */
static unsigned char *cbc_mac_input(const unsigned char *aad, size_t aad_len,
		const unsigned char *iv, size_t iv_len,
		const unsigned char *ct, size_t ct_len, size_t *out_len)
{
	unsigned char al[8];
	uint64_t aad_bits = (uint64_t)aad_len * 8;
	unsigned char *buf;
	size_t buf_len, off = 0;
	int i;

	for (i = 7; i >= 0; i--) {
		al[i] = (unsigned char)(aad_bits & 0xff);
		aad_bits >>= 8;
	}

	buf_len = aad_len + iv_len + ct_len + sizeof(al);
	buf = jwt_malloc(buf_len ? buf_len : 1);
	if (buf == NULL)
		return NULL; // LCOV_EXCL_LINE

	if (aad_len) { memcpy(buf + off, aad, aad_len); off += aad_len; }
	memcpy(buf + off, iv, iv_len); off += iv_len;
	if (ct_len) { memcpy(buf + off, ct, ct_len); off += ct_len; }
	memcpy(buf + off, al, sizeof(al));

	*out_len = buf_len;

	return buf;
}

/* Import the MAC key with a TRUNCATED-MAC HMAC policy (the JWE auth tag is the
 * leftmost @half octets of the HMAC), returning the matching alg in @mac_alg. */
static int import_hmac_key(const unsigned char *mac_key, size_t half,
		psa_algorithm_t hash, psa_key_usage_t usage,
		psa_algorithm_t *mac_alg, mbedtls_svc_key_id_t *kid)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st;

	*mac_alg = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(hash), half);
	*kid = MBEDTLS_SVC_KEY_ID_INIT;

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_algorithm(&attr, *mac_alg);

	st = psa_import_key(&attr, mac_key, half, kid);
	psa_reset_key_attributes(&attr);

	return st != PSA_SUCCESS;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content encryption (encrypt-then-MAC). */
int mbedtls_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	mbedtls_svc_key_id_t enc_kid = MBEDTLS_SVC_KEY_ID_INIT;
	mbedtls_svc_key_id_t mac_kid = MBEDTLS_SVC_KEY_ID_INIT;
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	psa_algorithm_t hash, mac_alg;
	const unsigned char *mac_key, *enc_key;
	unsigned char *pin = NULL, *out = NULL, *tag_out = NULL, *macbuf = NULL;
	size_t half, padded, pad, bs = 16, o1 = 0, o2 = 0, mac_in_len, tl = 0;
	int ret = 1, op_active = 0;

	if (cbc_params(enc, &hash, &half) || cek_len != jwe_enc_cek_len(enc) ||
	    iv_len != 16)
		return 1; // LCOV_EXCL_LINE

	/* @rfc{7518,5.2.2.1} MAC_KEY is the first half, ENC_KEY the second. */
	mac_key = cek;
	enc_key = cek + half;

	/* PKCS#7: always add 1..bs padding bytes. */
	pad = bs - (pt_len % bs);
	padded = pt_len + pad;

	pin = jwt_malloc(padded);
	out = jwt_malloc(padded + bs);
	tag_out = jwt_malloc(half);
	if (pin == NULL || out == NULL || tag_out == NULL)
		goto out; // LCOV_EXCL_LINE
	if (pt_len)
		memcpy(pin, pt, pt_len);
	memset(pin + pt_len, (int)pad, pad);

	/* AES-CBC with the supplied IV (multipart, so we can set the IV; the
	 * one-shot psa_cipher_encrypt would generate a random IV of its own). */
	if (import_aes_key(enc_key, half, PSA_ALG_CBC_NO_PADDING,
			   PSA_KEY_USAGE_ENCRYPT, &enc_kid))
		goto out; // LCOV_EXCL_LINE
	if (psa_cipher_encrypt_setup(&op, enc_kid, PSA_ALG_CBC_NO_PADDING))
		goto out; // LCOV_EXCL_LINE
	op_active = 1;
	if (psa_cipher_set_iv(&op, iv, iv_len) ||
	    psa_cipher_update(&op, pin, padded, out, padded + bs, &o1) ||
	    psa_cipher_finish(&op, out + o1, padded + bs - o1, &o2))
		goto out; // LCOV_EXCL_LINE
	op_active = 0;

	/* Tag = leftmost half of HMAC over AAD || IV || CT || AL. */
	macbuf = cbc_mac_input(aad, aad_len, iv, iv_len, out, o1 + o2,
			       &mac_in_len);
	if (macbuf == NULL)
		goto out; // LCOV_EXCL_LINE
	if (import_hmac_key(mac_key, half, hash, PSA_KEY_USAGE_SIGN_MESSAGE,
			    &mac_alg, &mac_kid))
		goto out; // LCOV_EXCL_LINE
	if (psa_mac_compute(mac_kid, mac_alg, macbuf, mac_in_len, tag_out, half,
			    &tl))
		goto out; // LCOV_EXCL_LINE

	*ct = out;
	*ct_len = o1 + o2;
	*tag = tag_out;
	*tag_len = half;
	out = NULL;
	tag_out = NULL;
	ret = 0;

out:
	if (op_active)
		psa_cipher_abort(&op); // LCOV_EXCL_LINE
	jwt_scrub_and_free(pin, padded);
	jwt_freemem(out);
	jwt_freemem(tag_out);
	jwt_freemem(macbuf);
	psa_destroy_key(enc_kid);
	psa_destroy_key(mac_kid);

	return ret;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content decryption. Verifies the tag in
 * constant time BEFORE decrypting. */
int mbedtls_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	mbedtls_svc_key_id_t enc_kid = MBEDTLS_SVC_KEY_ID_INIT;
	mbedtls_svc_key_id_t mac_kid = MBEDTLS_SVC_KEY_ID_INIT;
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	psa_algorithm_t hash, mac_alg;
	const unsigned char *mac_key, *enc_key;
	unsigned char *out = NULL, *macbuf = NULL;
	size_t half, pad, bs = 16, o1 = 0, o2 = 0, mac_in_len, outlen;
	int ret = 1, op_active = 0;

	if (cbc_params(enc, &hash, &half) || cek_len != jwe_enc_cek_len(enc) ||
	    iv_len != 16 || tag_len != half || ct_len == 0 || (ct_len % bs) != 0)
		return 1; // LCOV_EXCL_LINE

	mac_key = cek;
	enc_key = cek + half;

	/* @rfc{7518,5.2.2.2} Recompute and compare the tag in constant time before
	 * touching the ciphertext (psa_mac_verify is constant-time). */
	macbuf = cbc_mac_input(aad, aad_len, iv, iv_len, ct, ct_len, &mac_in_len);
	if (macbuf == NULL)
		return 1; // LCOV_EXCL_LINE
	if (import_hmac_key(mac_key, half, hash, PSA_KEY_USAGE_VERIFY_MESSAGE,
			    &mac_alg, &mac_kid)) {
		// LCOV_EXCL_START
		jwt_freemem(macbuf);
		return 1;
		// LCOV_EXCL_STOP
	}
	ret = psa_mac_verify(mac_kid, mac_alg, macbuf, mac_in_len, tag, half) ? 1 : 0;
	jwt_freemem(macbuf);
	psa_destroy_key(mac_kid);
	mac_kid = MBEDTLS_SVC_KEY_ID_INIT;
	if (ret)
		return 1;

	ret = 1;

	out = jwt_malloc(ct_len + bs);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (import_aes_key(enc_key, half, PSA_ALG_CBC_NO_PADDING,
			   PSA_KEY_USAGE_DECRYPT, &enc_kid))
		goto out; // LCOV_EXCL_LINE
	if (psa_cipher_decrypt_setup(&op, enc_kid, PSA_ALG_CBC_NO_PADDING))
		goto out; // LCOV_EXCL_LINE
	op_active = 1;
	if (psa_cipher_set_iv(&op, iv, iv_len) ||
	    psa_cipher_update(&op, ct, ct_len, out, ct_len + bs, &o1) ||
	    psa_cipher_finish(&op, out + o1, ct_len + bs - o1, &o2))
		goto out; // LCOV_EXCL_LINE
	op_active = 0;
	outlen = o1 + o2;

	/* Strip and validate PKCS#7 padding. The tag already authenticated the
	 * ciphertext, so a corrupt-padding path is not reachable with a valid tag;
	 * the check stays as defense in depth. */
	pad = out[outlen - 1];
	if (pad == 0 || pad > bs || pad > outlen)
		goto out; // LCOV_EXCL_LINE

	*pt = out;
	*pt_len = outlen - pad;
	out = NULL;
	ret = 0;

out:
	if (op_active)
		psa_cipher_abort(&op); // LCOV_EXCL_LINE
	jwt_scrub_and_free(out, ct_len + bs);
	psa_destroy_key(enc_kid);
	psa_destroy_key(mac_kid);

	return ret;
}

/* One AES-ECB block (16 bytes), the primitive under RFC 3394 key wrap. ECB has
 * no IV, so PSA returns exactly the 16-byte block. */
static int aes_ecb_block(mbedtls_svc_key_id_t kid, int encrypt,
			 const unsigned char in[16], unsigned char out[16])
{
	unsigned char tmp[32];
	size_t olen = 0;
	psa_status_t st;

	if (encrypt)
		st = psa_cipher_encrypt(kid, PSA_ALG_ECB_NO_PADDING, in, 16,
					tmp, sizeof(tmp), &olen);
	else
		st = psa_cipher_decrypt(kid, PSA_ALG_ECB_NO_PADDING, in, 16,
					tmp, sizeof(tmp), &olen);

	if (st != PSA_SUCCESS || olen != 16)
		return 1; // LCOV_EXCL_LINE

	memcpy(out, tmp, 16);

	return 0;
}

/* @rfc{3394} AES Key Wrap with a raw KEK, built on AES-ECB. (RFC 3394 / the KW
 * "A6A6..." ICV, NOT RFC 5649 KWP, which must not be used for JWE.) */
static int kw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *in, size_t in_len,
		       unsigned char **out, size_t *out_len)
{
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	unsigned char a[8], b[16], *r;
	unsigned char *buf = NULL;
	size_t n, i, j;
	int k, ret = 1;

	if ((kek_len != 16 && kek_len != 24 && kek_len != 32) ||
	    in_len < 16 || (in_len % 8) != 0)
		return 1; // LCOV_EXCL_LINE

	n = in_len / 8;

	if (import_aes_key(kek, kek_len, PSA_ALG_ECB_NO_PADDING,
			   PSA_KEY_USAGE_ENCRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(in_len + 8);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	memset(a, 0xA6, 8);		/* A = default IV */
	memcpy(buf + 8, in, in_len);	/* R[1..n] = P[1..n] */

	for (j = 0; j < 6; j++) {
		for (i = 1; i <= n; i++) {
			uint64_t t = (uint64_t)(n * j + i);

			r = buf + i * 8;
			memcpy(b, a, 8);
			memcpy(b + 8, r, 8);
			if (aes_ecb_block(kid, 1, b, b))
				goto out; // LCOV_EXCL_LINE
			memcpy(a, b, 8);	/* A = MSB64(B) ^ t */
			for (k = 0; k < 8; k++)
				a[7 - k] ^= (unsigned char)(t >> (8 * k));
			memcpy(r, b + 8, 8);	/* R[i] = LSB64(B) */
		}
	}

	memcpy(buf, a, 8);		/* C[0] = A */

	*out = buf;
	*out_len = in_len + 8;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	psa_destroy_key(kid);

	return ret;
}

/* @rfc{3394} AES Key Unwrap with a raw KEK. */
static int kw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **out, size_t *out_len)
{
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	unsigned char a[8], b[16], diff = 0, *r;
	unsigned char *buf = NULL;
	size_t n, i, j;
	int k, ret = 1;

	if ((kek_len != 16 && kek_len != 24 && kek_len != 32) ||
	    in_len < 24 || (in_len % 8) != 0)
		return 1;

	n = in_len / 8 - 1;

	if (import_aes_key(kek, kek_len, PSA_ALG_ECB_NO_PADDING,
			   PSA_KEY_USAGE_DECRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(in_len - 8);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	memcpy(a, in, 8);		/* A = C[0] */
	memcpy(buf, in + 8, in_len - 8);/* R[1..n] = C[1..n] */

	for (j = 6; j-- > 0; ) {
		for (i = n; i >= 1; i--) {
			uint64_t t = (uint64_t)(n * j + i);

			r = buf + (i - 1) * 8;
			for (k = 0; k < 8; k++)
				a[7 - k] ^= (unsigned char)(t >> (8 * k));
			memcpy(b, a, 8);
			memcpy(b + 8, r, 8);
			if (aes_ecb_block(kid, 0, b, b))
				goto out; // LCOV_EXCL_LINE
			memcpy(a, b, 8);	/* A = MSB64(B) */
			memcpy(r, b + 8, 8);	/* R[i] = LSB64(B) */
		}
	}

	/* Integrity: the recovered A must equal the RFC 3394 default IV. */
	for (i = 0; i < 8; i++)
		diff |= a[i] ^ 0xA6;
	if (diff)
		goto out;

	*out = buf;
	*out_len = in_len - 8;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, in_len - 8);
	psa_destroy_key(kid);

	return ret;
}

/* @rfc{7518,4.4} AES Key Wrap of the CEK with the recipient's oct key. */
int mbedtls_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
			size_t cek_len, unsigned char **out, size_t *out_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

/* @rfc{7518,4.4} AES Key Unwrap with the recipient's oct key. */
int mbedtls_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
			  size_t in_len, unsigned char **cek, size_t *cek_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
}

/* @rfc{7518,4.4} AES Key Wrap / Unwrap with a raw KEK (ECDH-ES+A*KW). */
int mbedtls_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

int mbedtls_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			      const unsigned char *in, size_t in_len,
			      unsigned char **cek, size_t *cek_len)
{
	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
}

/* Map an RSA-OAEP alg to its PSA hash. The same hash is used for the OAEP label
 * digest and the MGF1, exactly what JWE requires. */
static psa_algorithm_t oaep_hash(jwe_key_alg_t alg)
{
	if (alg == JWE_ALG_RSA_OAEP)
		return PSA_ALG_SHA_1;
	if (alg == JWE_ALG_RSA_OAEP_256)
		return PSA_ALG_SHA_256;

	return PSA_ALG_NONE; // LCOV_EXCL_LINE
}

/* @rfc{7518,4.3} RSAES-OAEP encryption of the CEK to the recipient public key. */
int mbedtls_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	psa_algorithm_t hash = oaep_hash(alg), oalg;
	unsigned char *buf = NULL;
	size_t rsa_len, olen = 0;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA || hash == PSA_ALG_NONE)
		return 1; // LCOV_EXCL_LINE

	oalg = PSA_ALG_RSA_OAEP(hash);
	rsa_len = (jk->bits + 7) / 8;

	if (mbedtls_jwk_to_psa(jk, 0, oalg, PSA_KEY_USAGE_ENCRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(rsa_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (psa_asymmetric_encrypt(kid, oalg, cek, cek_len, NULL, 0,
				   buf, rsa_len, &olen))
		goto out; // LCOV_EXCL_LINE

	*out = buf;
	*out_len = olen;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	psa_destroy_key(kid);

	return ret;
}

/* @rfc{7518,4.3} RSAES-OAEP decryption of the JWE Encrypted Key. A failure here
 * is funnelled by the caller into the uniform random-CEK path (11.5). */
int mbedtls_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *in, size_t in_len,
			    unsigned char **cek, size_t *cek_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	psa_algorithm_t hash = oaep_hash(alg), oalg;
	unsigned char *buf = NULL;
	size_t rsa_len, olen = 0;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA || hash == PSA_ALG_NONE)
		return 1; // LCOV_EXCL_LINE

	oalg = PSA_ALG_RSA_OAEP(hash);
	rsa_len = (jk->bits + 7) / 8;

	if (in_len != rsa_len)
		return 1;

	if (mbedtls_jwk_to_psa(jk, 1, oalg, PSA_KEY_USAGE_DECRYPT, &kid))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(rsa_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	/* A decryption/padding failure returns non-zero here. */
	if (psa_asymmetric_decrypt(kid, oalg, in, in_len, NULL, 0,
				   buf, rsa_len, &olen))
		goto out;

	*cek = buf;
	*cek_len = olen;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, rsa_len);
	psa_destroy_key(kid);

	return ret;
}

/* ======================== ECDH-ES (RFC 7518 4.6) ======================== */

/* The derived-key length (octets) and ASCII AlgorithmID for the Concat KDF.
 * ECDH-ES (Direct): AlgorithmID = "enc", length = enc CEK length. ECDH-ES+A*KW:
 * AlgorithmID = "alg", length = the AES-KW key size. */
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

/* @rfc{7518,4.6.2} Concat KDF (NIST SP 800-56A 5.8.1) with SHA-256. JWE needs
 * <= 32 octets (one SHA-256 block), so a single round suffices. */
static int concat_kdf(const unsigned char *z, size_t z_len,
		      const char *algid, const unsigned char *apu, size_t apu_len,
		      const unsigned char *apv, size_t apv_len,
		      size_t keydatalen, unsigned char *out)
{
	unsigned char hash[32];
	unsigned char *buf;
	size_t algid_len = strlen(algid);
	size_t buf_len, off = 0, hlen = 0;
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

	/* counter || Z || OtherInfo (each length-prefixed) || SuppPubInfo */
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

	if (psa_hash_compute(PSA_ALG_SHA_256, buf, off, hash, sizeof(hash),
			     &hlen) == 0) {
		memcpy(out, hash, keydatalen);
		ret = 0;
	}

	jwt_scrub_and_free(buf, buf_len);

	return ret;
}

/* Build an "epk" {kty:EC,crv,x,y} JWK from a PSA-exported NIST public point
 * (0x04 || X || Y, each @fieldlen bytes). */
static jwt_json_t *epk_ec_to_json(const unsigned char *pub, size_t pub_len,
				  const char *crv, size_t fieldlen)
{
	jwt_json_t *epk;
	char_auto *x_b64 = NULL, *y_b64 = NULL;

	if (pub_len != 1 + fieldlen * 2 || pub[0] != 0x04)
		return NULL; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&x_b64, (char *)pub + 1, (int)fieldlen) <= 0 ||
	    jwt_base64uri_encode(&y_b64, (char *)pub + 1 + fieldlen,
				 (int)fieldlen) <= 0)
		return NULL; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		return NULL; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str("EC"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));
	jwt_json_obj_set(epk, "y", jwt_json_create_str(y_b64));

	return epk;
}

/* Read a peer NIST public point from an "epk" {kty:EC,crv,x,y} JWK into the
 * uncompressed-point form (0x04 || X || Y) PSA agreement expects. */
static int epk_ec_from_json(jwt_json_t *epk, const char *want_crv,
			    size_t fieldlen, unsigned char *out, size_t out_cap,
			    size_t *out_len)
{
	jwt_json_t *jkty, *jcrv, *jx, *jy;
	const char *kty, *crv;
	unsigned char *xb = NULL, *yb = NULL;
	int xlen = 0, ylen = 0, ret = 1;
	size_t ptlen = 1 + fieldlen * 2;

	if (ptlen > out_cap)
		return 1; // LCOV_EXCL_LINE

	jkty = jwt_json_obj_get(epk, "kty");
	jcrv = jwt_json_obj_get(epk, "crv");
	jx = jwt_json_obj_get(epk, "x");
	jy = jwt_json_obj_get(epk, "y");
	if (!jkty || !jcrv || !jx || !jy || !jwt_json_is_string(jkty) ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx) ||
	    !jwt_json_is_string(jy))
		return 1; // LCOV_EXCL_LINE

	kty = jwt_json_str_val(jkty);
	crv = jwt_json_str_val(jcrv);
	if (strcmp(kty, "EC") || strcmp(crv, want_crv))
		return 1;

	xb = jwt_base64uri_decode(jwt_json_str_val(jx), &xlen);
	yb = jwt_base64uri_decode(jwt_json_str_val(jy), &ylen);
	if (xb == NULL || yb == NULL || (size_t)xlen > fieldlen ||
	    (size_t)ylen > fieldlen)
		goto out; // LCOV_EXCL_LINE

	memset(out, 0, ptlen);
	out[0] = 0x04;
	memcpy(out + 1 + (fieldlen - (size_t)xlen), xb, (size_t)xlen);
	memcpy(out + 1 + fieldlen + (fieldlen - (size_t)ylen), yb, (size_t)ylen);
	*out_len = ptlen;
	ret = 0;

out:
	jwt_freemem(xb);
	jwt_freemem(yb);

	return ret;
}

/* Build an "epk" {kty:OKP,crv,x} JWK from a PSA-exported X-curve public key (the
 * raw little-endian u-coordinate). */
static jwt_json_t *epk_okp_to_json(const unsigned char *pub, size_t pub_len,
				   const char *crv)
{
	jwt_json_t *epk;
	char_auto *x_b64 = NULL;

	if (jwt_base64uri_encode(&x_b64, (char *)pub, (int)pub_len) <= 0)
		return NULL; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		return NULL; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str("OKP"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));

	return epk;
}

/* Read a peer X-curve public key (raw little-endian u-coordinate) from an "epk"
 * {kty:OKP,crv,x} JWK. */
static int epk_okp_from_json(jwt_json_t *epk, const char *want_crv,
			     size_t keylen, unsigned char *out, size_t *out_len)
{
	jwt_json_t *jkty, *jcrv, *jx;
	const char *kty, *crv;
	unsigned char *xb = NULL;
	int xlen = 0, ret = 1;

	jkty = jwt_json_obj_get(epk, "kty");
	jcrv = jwt_json_obj_get(epk, "crv");
	jx = jwt_json_obj_get(epk, "x");
	if (!jkty || !jcrv || !jx || !jwt_json_is_string(jkty) ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx))
		return 1; // LCOV_EXCL_LINE

	kty = jwt_json_str_val(jkty);
	crv = jwt_json_str_val(jcrv);
	if (strcmp(kty, "OKP") || strcmp(crv, want_crv))
		return 1;

	xb = jwt_base64uri_decode(jwt_json_str_val(jx), &xlen);
	if (xb == NULL || (size_t)xlen != keylen)
		goto out; // LCOV_EXCL_LINE

	memcpy(out, xb, keylen);
	*out_len = keylen;
	ret = 0;

out:
	jwt_freemem(xb);

	return ret;
}

/* Generate an ephemeral ECDH keypair on the given curve. PSA here cannot
 * psa_generate_key() a Montgomery pair, so for the X-curves we generate a random
 * scalar and import it (any value of the right length is a valid X25519/X448
 * secret; clamping is applied internally). NIST curves use psa_generate_key. */
static int gen_ephemeral(psa_ecc_family_t fam, size_t bits, int is_okp,
			 size_t fieldlen, mbedtls_svc_key_id_t *kid)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st;

	*kid = MBEDTLS_SVC_KEY_ID_INIT;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(fam));
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	if (is_okp) {
		unsigned char scalar[PSA_BITS_TO_BYTES(521)];

		if (psa_generate_random(scalar, fieldlen)) {
			// LCOV_EXCL_START
			psa_reset_key_attributes(&attr);
			return 1;
			// LCOV_EXCL_STOP
		}
		st = psa_import_key(&attr, scalar, fieldlen, kid);
		mbedtls_platform_zeroize(scalar, sizeof(scalar));
	} else {
		psa_set_key_bits(&attr, bits);
		st = psa_generate_key(&attr, kid);
	}

	psa_reset_key_attributes(&attr);

	return st != PSA_SUCCESS;
}

/* @rfc{7518,4.6} ECDH-ES key agreement via PSA. On encrypt an ephemeral keypair
 * is generated on the recipient's curve, its "epk" public half written to @hdr,
 * and the agreed secret derived against the recipient's public key. On decrypt
 * the "epk" is read from @hdr and agreement runs against the recipient private
 * key. The Concat-KDF output (CEK for ECDH-ES, KEK for +A*KW) is returned in
 * @dk. */
int mbedtls_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
			const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
			unsigned char **dk, size_t *dk_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	const char *crv = key->curve, *algid = NULL;
	unsigned char zbuf[PSA_BITS_TO_BYTES(521)];
	unsigned char peer[1 + 2 * PSA_BITS_TO_BYTES(521)];
	unsigned char *apu = NULL, *apv = NULL, *out = NULL;
	size_t fieldlen, keydatalen = 0, z_len = 0, peer_len = 0;
	int apu_len = 0, apv_len = 0, is_okp, ret = 1;
	jwt_json_t *japu, *japv, *jepk;

	/* The recipient is a NIST EC key or an OKP X-curve key (both held as
	 * importable material). An OKP Ed-curve has no ECDH and is rejected. */
	if (jk == NULL ||
	    (jk->kty != JWK_KEY_TYPE_EC &&
	     !(jk->kty == JWK_KEY_TYPE_OKP && !jk->okp_is_ed)))
		return 1; // LCOV_EXCL_LINE

	is_okp = (jk->kty == JWK_KEY_TYPE_OKP);
	fieldlen = PSA_BITS_TO_BYTES(jk->bits);

	/* Only the JOSE ECDH-ES curves are permitted: NIST P-256/384/521 and the
	 * Montgomery X-curves. Other valid EC keys (e.g. secp256k1) are accepted
	 * by setkey but must fail here. */
	if (!is_okp && jk->ecc_family != PSA_ECC_FAMILY_SECP_R1)
		goto out;

	if (ecdh_keydatalen(alg, enc, &keydatalen, &algid))
		goto out; // LCOV_EXCL_LINE

	if (psa_crypto_init() != PSA_SUCCESS)
		goto out; // LCOV_EXCL_LINE

	out = jwt_malloc(keydatalen);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (for_encrypt) {
		unsigned char eph_pub[1 + 2 * PSA_BITS_TO_BYTES(521)];
		size_t eph_pub_len = 0;

		/* Ephemeral keypair on the recipient's curve. */
		if (gen_ephemeral(jk->ecc_family, jk->bits, is_okp, fieldlen, &kid))
			goto out; // LCOV_EXCL_LINE

		if (psa_export_public_key(kid, eph_pub, sizeof(eph_pub),
					  &eph_pub_len))
			goto out; // LCOV_EXCL_LINE

		jepk = is_okp
			? epk_okp_to_json(eph_pub, eph_pub_len, crv)
			: epk_ec_to_json(eph_pub, eph_pub_len, crv, fieldlen);
		if (jepk == NULL)
			goto out; // LCOV_EXCL_LINE
		jwt_json_obj_set(hdr, "epk", jepk);

		/* peer = recipient public key material. */
		if (jk->pub == NULL || jk->pub_len > sizeof(peer))
			goto out; // LCOV_EXCL_LINE
		memcpy(peer, jk->pub, jk->pub_len);
		peer_len = jk->pub_len;
	} else {
		jepk = jwt_json_obj_get(hdr, "epk");
		if (jepk == NULL)
			goto out;
		if (is_okp) {
			if (epk_okp_from_json(jepk, crv, fieldlen, peer,
					      &peer_len))
				goto out;
		} else {
			if (epk_ec_from_json(jepk, crv, fieldlen, peer,
					     sizeof(peer), &peer_len))
				goto out;
		}

		/* Import the recipient private key for agreement. */
		if (mbedtls_jwk_to_psa(jk, 1, PSA_ALG_ECDH,
				       PSA_KEY_USAGE_DERIVE, &kid))
			goto out; // LCOV_EXCL_LINE
	}

	/* Z = ECDH(our_priv, peer_pub). PSA returns the agreed secret of fixed
	 * field length: the x-coordinate (NIST, big-endian) or the raw shared
	 * value (Montgomery, little-endian) — exactly what the Concat-KDF wants. */
	if (psa_raw_key_agreement(PSA_ALG_ECDH, kid, peer, peer_len,
				  zbuf, sizeof(zbuf), &z_len))
		goto out; // LCOV_EXCL_LINE

	/* apu/apv (optional PartyU/PartyV info), fed to the KDF as-is. */
	japu = jwt_json_obj_get(hdr, "apu");
	if (japu && jwt_json_is_string(japu))
		apu = jwt_base64uri_decode(jwt_json_str_val(japu), &apu_len);
	japv = jwt_json_obj_get(hdr, "apv");
	if (japv && jwt_json_is_string(japv))
		apv = jwt_base64uri_decode(jwt_json_str_val(japv), &apv_len);

	if (concat_kdf(zbuf, z_len, algid,
		       apu, apu_len < 0 ? 0 : (size_t)apu_len,
		       apv, apv_len < 0 ? 0 : (size_t)apv_len, keydatalen, out))
		goto out; // LCOV_EXCL_LINE

	*dk = out;
	*dk_len = keydatalen;
	out = NULL;
	ret = 0;

out:
	mbedtls_platform_zeroize(zbuf, sizeof(zbuf));
	jwt_scrub_and_free(out, keydatalen);
	jwt_freemem(apu);
	jwt_freemem(apv);
	psa_destroy_key(kid);

	return ret;
}
