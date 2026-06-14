/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/nist_kw.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/platform_util.h>

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

/* Seed a fresh CTR-DRBG from the entropy source. The caller frees both with
 * drbg_free(). Returns 0 on success. Seeding per-call mirrors the MbedTLS
 * sign path; it is simple and avoids global state. */
static int drbg_init(mbedtls_entropy_context *entropy,
		     mbedtls_ctr_drbg_context *drbg)
{
	const char *pers = "libjwt_jwe";

	mbedtls_entropy_init(entropy);
	mbedtls_ctr_drbg_init(drbg);

	if (mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy,
				  (const unsigned char *)pers, strlen(pers)))
		return 1; // LCOV_EXCL_LINE

	return 0;
}

static void drbg_free(mbedtls_entropy_context *entropy,
		      mbedtls_ctr_drbg_context *drbg)
{
	mbedtls_ctr_drbg_free(drbg);
	mbedtls_entropy_free(entropy);
}

/* @rfc{7516,5.1} CSPRNG for CEK/IV generation and the @rfc{7516,11.5}
 * random-CEK fallback. Backed by MbedTLS CTR-DRBG. */
int mbedtls_rng(unsigned char *out, size_t len)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	int ret = 1;

	if (out == NULL || len == 0)
		return 1; // LCOV_EXCL_LINE

	if (drbg_init(&entropy, &drbg))
		return 1; // LCOV_EXCL_LINE

	if (mbedtls_ctr_drbg_random(&drbg, out, len) == 0)
		ret = 0;

	drbg_free(&entropy, &drbg);

	return ret;
}

/* @rfc{7518,5.3} AES GCM content encryption. */
int mbedtls_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	mbedtls_gcm_context gcm;
	unsigned char *out = NULL, *t = NULL;
	int ret = 1;

	if (!enc_is_gcm(enc) || cek_len != jwe_enc_cek_len(enc))
		return 1; // LCOV_EXCL_LINE

	mbedtls_gcm_init(&gcm);

	out = jwt_malloc(pt_len ? pt_len : 1);
	t = jwt_malloc(GCM_TAG_LEN);
	if (out == NULL || t == NULL)
		goto out; // LCOV_EXCL_LINE

	/* setkey takes the key length in BITS. */
	if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, cek,
			       (unsigned int)(cek_len * 8)))
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt_len,
				      iv, iv_len, aad, aad_len, pt, out,
				      GCM_TAG_LEN, t))
		goto out; // LCOV_EXCL_LINE

	*ct = out;
	*ct_len = pt_len;
	*tag = t;
	*tag_len = GCM_TAG_LEN;
	out = NULL;
	t = NULL;
	ret = 0;

out:
	jwt_freemem(out);
	jwt_freemem(t);
	mbedtls_gcm_free(&gcm);

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
	mbedtls_gcm_context gcm;
	unsigned char *out = NULL;
	int ret = 1;

	if (!enc_is_gcm(enc) || cek_len != jwe_enc_cek_len(enc) ||
	    tag_len != GCM_TAG_LEN)
		return 1; // LCOV_EXCL_LINE

	mbedtls_gcm_init(&gcm);

	out = jwt_malloc(ct_len ? ct_len : 1);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, cek,
			       (unsigned int)(cek_len * 8)))
		goto out; // LCOV_EXCL_LINE

	/* auth_decrypt performs a constant-time tag check; a non-zero return
	 * (MBEDTLS_ERR_GCM_AUTH_FAILED) is the authentication failure. */
	if (mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, iv_len, aad, aad_len,
				     tag, GCM_TAG_LEN, ct, out))
		goto out;

	*pt = out;
	*pt_len = ct_len;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(out, ct_len ? ct_len : 1);
	mbedtls_gcm_free(&gcm);

	return ret;
}

/* @rfc{7518,5.2} Map a CBC-HMAC enc to its AES key bits, HMAC digest, and the
 * (equal) MAC/ENC key half-length, which is also the truncated tag length. */
static int cbc_params(jwe_enc_t enc, unsigned int *keybits,
		      mbedtls_md_type_t *md, size_t *half)
{
	switch (enc) {
	case JWE_ENC_A128CBC_HS256:
		*keybits = 128; *md = MBEDTLS_MD_SHA256; *half = 16;
		return 0;
	case JWE_ENC_A192CBC_HS384:
		*keybits = 192; *md = MBEDTLS_MD_SHA384; *half = 24;
		return 0;
	case JWE_ENC_A256CBC_HS512:
		*keybits = 256; *md = MBEDTLS_MD_SHA512; *half = 32;
		return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.2.2.1} HMAC over AAD || IV || CT || AL, where AL is the 64-bit
 * big-endian bit-length of the AAD, truncated to the leftmost @half octets.
 * @out must hold at least 64 bytes (max SHA-512). */
static int cbc_hmac_tag(mbedtls_md_type_t mdtype, const unsigned char *mac_key,
			size_t half, const unsigned char *aad, size_t aad_len,
			const unsigned char *iv, size_t iv_len,
			const unsigned char *ct, size_t ct_len,
			unsigned char *out)
{
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(mdtype);
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

	if (md != NULL &&
	    mbedtls_md_hmac(md, mac_key, half, buf, buf_len, out) == 0)
		ret = 0;

	jwt_freemem(buf);

	return ret;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content encryption (encrypt-then-MAC). */
int mbedtls_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	mbedtls_aes_context aes;
	mbedtls_md_type_t mdtype;
	unsigned int keybits;
	unsigned char hmac[64], ivc[16];
	unsigned char *out = NULL, *t = NULL;
	const unsigned char *mac_key, *enc_key;
	size_t half, padded, pad, bs = 16;
	int ret = 1;

	if (cbc_params(enc, &keybits, &mdtype, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16)
		return 1; // LCOV_EXCL_LINE

	/* @rfc{7518,5.2.2.1} MAC_KEY is the first half, ENC_KEY the second. */
	mac_key = cek;
	enc_key = cek + half;

	mbedtls_aes_init(&aes);

	/* PKCS#7: always add 1..bs padding bytes. */
	pad = bs - (pt_len % bs);
	padded = pt_len + pad;

	out = jwt_malloc(padded);
	t = jwt_malloc(half);
	if (out == NULL || t == NULL)
		goto out; // LCOV_EXCL_LINE
	if (pt_len)
		memcpy(out, pt, pt_len);
	memset(out + pt_len, (int)pad, pad);

	/* mbedtls_aes_crypt_cbc updates the IV buffer in place; use a copy. */
	memcpy(ivc, iv, 16);
	if (mbedtls_aes_setkey_enc(&aes, enc_key, keybits) ||
	    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, ivc,
				  out, out))
		goto out; // LCOV_EXCL_LINE

	if (cbc_hmac_tag(mdtype, mac_key, half, aad, aad_len, iv, iv_len,
			 out, padded, hmac))
		goto out; // LCOV_EXCL_LINE
	memcpy(t, hmac, half);

	*ct = out;
	*ct_len = padded;
	*tag = t;
	*tag_len = half;
	out = NULL;
	t = NULL;
	ret = 0;

out:
	jwt_freemem(out);
	jwt_freemem(t);
	mbedtls_aes_free(&aes);

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
	mbedtls_aes_context aes;
	mbedtls_md_type_t mdtype;
	unsigned int keybits;
	unsigned char hmac[64], ivc[16];
	unsigned char *out = NULL;
	const unsigned char *mac_key, *enc_key;
	size_t half, pad, bs = 16;
	int ret = 1;

	if (cbc_params(enc, &keybits, &mdtype, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16 ||
	    tag_len != half || ct_len == 0 || (ct_len % bs) != 0)
		return 1; // LCOV_EXCL_LINE

	mac_key = cek;
	enc_key = cek + half;

	/* @rfc{7518,5.2.2.2} Recompute and compare the tag in constant time
	 * before touching the ciphertext. */
	if (cbc_hmac_tag(mdtype, mac_key, half, aad, aad_len, iv, iv_len,
			 ct, ct_len, hmac))
		return 1; // LCOV_EXCL_LINE
	if (mbedtls_ct_memcmp(hmac, tag, half) != 0)
		return 1;

	mbedtls_aes_init(&aes);

	out = jwt_malloc(ct_len);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	memcpy(ivc, iv, 16);
	if (mbedtls_aes_setkey_dec(&aes, enc_key, keybits) ||
	    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct_len, ivc,
				  ct, out))
		goto out; // LCOV_EXCL_LINE

	/* Strip and validate PKCS#7 padding. The tag already authenticated the
	 * ciphertext, so a corrupt-padding path is not reachable with a valid
	 * tag; the check stays as defense in depth. */
	pad = out[ct_len - 1];
	if (pad == 0 || pad > bs || pad > ct_len)
		goto out; // LCOV_EXCL_LINE

	*pt = out;
	*pt_len = ct_len - pad;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(out, ct_len);
	mbedtls_aes_free(&aes);

	return ret;
}

/* @rfc{7518,4.4} AES Key Wrap (RFC 3394) with a raw KEK via mbedtls_nist_kw.
 * MBEDTLS_KW_MODE_KW is RFC 3394 (the A6A6… ICV); KWP is RFC 5649 and must not
 * be used for JWE. */
static int kw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *in, size_t in_len,
		       unsigned char **out, size_t *out_len)
{
	mbedtls_nist_kw_context kw;
	unsigned char *buf = NULL;
	size_t olen = 0;
	int ret = 1;

	if ((kek_len != 16 && kek_len != 24 && kek_len != 32) ||
	    in_len < 16 || (in_len % 8) != 0)
		return 1; // LCOV_EXCL_LINE

	mbedtls_nist_kw_init(&kw);

	buf = jwt_malloc(in_len + 8);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, kek,
				   (unsigned int)(kek_len * 8), 1))
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW, in, in_len,
				 buf, &olen, in_len + 8))
		goto out; // LCOV_EXCL_LINE

	*out = buf;
	*out_len = olen;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	mbedtls_nist_kw_free(&kw);

	return ret;
}

/* @rfc{7518,4.4} AES Key Unwrap (RFC 3394) with a raw KEK. */
static int kw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **out, size_t *out_len)
{
	mbedtls_nist_kw_context kw;
	unsigned char *buf = NULL;
	size_t olen = 0;
	int ret = 1;

	if ((kek_len != 16 && kek_len != 24 && kek_len != 32) ||
	    in_len < 24 || (in_len % 8) != 0)
		return 1;

	mbedtls_nist_kw_init(&kw);

	buf = jwt_malloc(in_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, kek,
				   (unsigned int)(kek_len * 8), 0))
		goto out; // LCOV_EXCL_LINE

	/* A non-zero return (MBEDTLS_ERR_CIPHER_AUTH_FAILED) is the RFC 3394
	 * integrity-check failure on the recovered A6 IV. */
	if (mbedtls_nist_kw_unwrap(&kw, MBEDTLS_KW_MODE_KW, in, in_len,
				   buf, &olen, in_len))
		goto out;

	*out = buf;
	*out_len = olen;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, in_len);
	mbedtls_nist_kw_free(&kw);

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

/* Map an RSA-OAEP alg to its MbedTLS digest. In MbedTLS the same hash is used
 * for the OAEP encoding AND the MGF1 (mbedtls_rsa_set_padding has no separate
 * MGF1 setter), exactly what JWE requires. */
static mbedtls_md_type_t oaep_md(jwe_key_alg_t alg)
{
	if (alg == JWE_ALG_RSA_OAEP)
		return MBEDTLS_MD_SHA1;
	if (alg == JWE_ALG_RSA_OAEP_256)
		return MBEDTLS_MD_SHA256;

	return MBEDTLS_MD_NONE; // LCOV_EXCL_LINE
}

/* @rfc{7518,4.3} RSAES-OAEP encryption of the CEK to the recipient public key.
 * The recipient's native MbedTLS RSA key is on the JWK. */
int mbedtls_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_rsa_context *rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_md_type_t md = oaep_md(alg);
	unsigned char *buf = NULL;
	size_t rsa_len;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA || md == MBEDTLS_MD_NONE)
		return 1; // LCOV_EXCL_LINE

	rsa = (mbedtls_rsa_context *)&jk->rsa;
	rsa_len = mbedtls_rsa_get_len(rsa);

	if (drbg_init(&entropy, &drbg))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(rsa_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md))
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &drbg,
					   NULL, 0, cek_len, cek, buf))
		goto out; // LCOV_EXCL_LINE

	*out = buf;
	*out_len = rsa_len;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	drbg_free(&entropy, &drbg);

	return ret;
}

/* @rfc{7518,4.3} RSAES-OAEP decryption of the JWE Encrypted Key. A failure
 * here is funnelled by the caller into the uniform random-CEK path (11.5). */
int mbedtls_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *in, size_t in_len,
			    unsigned char **cek, size_t *cek_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_rsa_context *rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_md_type_t md = oaep_md(alg);
	unsigned char *buf = NULL;
	size_t rsa_len, olen = 0;
	int ret = 1;

	if (jk == NULL || jk->kty != JWK_KEY_TYPE_RSA || md == MBEDTLS_MD_NONE)
		return 1; // LCOV_EXCL_LINE

	rsa = (mbedtls_rsa_context *)&jk->rsa;
	rsa_len = mbedtls_rsa_get_len(rsa);

	if (in_len != rsa_len)
		return 1;

	if (drbg_init(&entropy, &drbg))
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(rsa_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md))
		goto out; // LCOV_EXCL_LINE

	/* A decryption/padding failure returns non-zero here. */
	if (mbedtls_rsa_rsaes_oaep_decrypt(rsa, mbedtls_ctr_drbg_random, &drbg,
					   NULL, 0, &olen, in, buf, rsa_len))
		goto out;

	*cek = buf;
	*cek_len = olen;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, rsa_len);
	drbg_free(&entropy, &drbg);

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

	if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		       buf, off, hash) == 0) {
		memcpy(out, hash, keydatalen);
		ret = 0;
	}

	jwt_scrub_and_free(buf, buf_len);

	return ret;
}

/* NIST curve coordinate length in octets, and the JWK "crv" name. */
static int nist_crv_info(mbedtls_ecp_group_id gid, size_t *fieldlen,
			 const char **crv)
{
	switch (gid) {
	case MBEDTLS_ECP_DP_SECP256R1:
		*fieldlen = 32; *crv = "P-256"; return 0;
	case MBEDTLS_ECP_DP_SECP384R1:
		*fieldlen = 48; *crv = "P-384"; return 0;
	case MBEDTLS_ECP_DP_SECP521R1:
		*fieldlen = 66; *crv = "P-521"; return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* Is this a Montgomery X-curve (X25519/X448)? */
static int gid_is_montgomery(mbedtls_ecp_group_id gid)
{
	return gid == MBEDTLS_ECP_DP_CURVE25519 ||
	       gid == MBEDTLS_ECP_DP_CURVE448;
}

/* X25519/X448 raw key length and JWK "crv" name. */
static int okp_crv_info(mbedtls_ecp_group_id gid, size_t *keylen,
			const char **crv)
{
	if (gid == MBEDTLS_ECP_DP_CURVE25519) {
		*keylen = 32; *crv = "X25519"; return 0;
	}
	if (gid == MBEDTLS_ECP_DP_CURVE448) {
		*keylen = 56; *crv = "X448"; return 0;
	}
	return 1; // LCOV_EXCL_LINE
}

/* Build an "epk" {kty:EC,crv,x,y} JWK from an ephemeral NIST public point. */
static jwt_json_t *epk_ec_to_json(const mbedtls_ecp_point *Q, const char *crv,
				  size_t fieldlen)
{
	jwt_json_t *epk = NULL;
	char_auto *x_b64 = NULL, *y_b64 = NULL;
	unsigned char xb[66], yb[66];

	if (mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), xb, fieldlen) ||
	    mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), yb, fieldlen))
		return NULL; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&x_b64, (char *)xb, (int)fieldlen) <= 0 ||
	    jwt_base64uri_encode(&y_b64, (char *)yb, (int)fieldlen) <= 0)
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

/* Read a peer NIST public point from an "epk" {kty:EC,crv,x,y} JWK. */
static int epk_ec_from_json(jwt_json_t *epk, const char *want_crv,
			    const mbedtls_ecp_group *grp,
			    mbedtls_ecp_point *Q, size_t fieldlen)
{
	jwt_json_t *jkty, *jcrv, *jx, *jy;
	const char *kty, *crv;
	unsigned char *xb = NULL, *yb = NULL, *point = NULL;
	int xlen = 0, ylen = 0, ret = 1;
	size_t ptlen;

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

	/* Uncompressed point: 0x04 || X || Y, each left-padded to fieldlen. */
	ptlen = 1 + fieldlen * 2;
	point = jwt_malloc(ptlen);
	if (point == NULL)
		goto out; // LCOV_EXCL_LINE
	memset(point, 0, ptlen);
	point[0] = 0x04;
	memcpy(point + 1 + (fieldlen - (size_t)xlen), xb, (size_t)xlen);
	memcpy(point + 1 + fieldlen + (fieldlen - (size_t)ylen), yb,
	       (size_t)ylen);

	if (mbedtls_ecp_point_read_binary(grp, Q, point, ptlen) == 0 &&
	    mbedtls_ecp_check_pubkey(grp, Q) == 0)
		ret = 0;

out: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	jwt_freemem(xb);
	jwt_freemem(yb);
	jwt_freemem(point);

	return ret;
}

/* Build an "epk" {kty:OKP,crv,x} JWK from an ephemeral X-curve public point.
 * The Montgomery U-coordinate is emitted little-endian (RFC 7748/JWE wire). */
static jwt_json_t *epk_okp_to_json(const mbedtls_ecp_point *Q, const char *crv,
				   size_t keylen)
{
	jwt_json_t *epk = NULL;
	char_auto *x_b64 = NULL;
	unsigned char xb[56];

	if (mbedtls_mpi_write_binary_le(&Q->MBEDTLS_PRIVATE(X), xb, keylen))
		return NULL; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&x_b64, (char *)xb, (int)keylen) <= 0)
		return NULL; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		return NULL; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str("OKP"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));

	return epk;
}

/* Read a peer X-curve public point from an "epk" {kty:OKP,crv,x} JWK. The
 * Montgomery U-coordinate "x" is little-endian on the wire. */
static int epk_okp_from_json(jwt_json_t *epk, const char *want_crv,
			     mbedtls_ecp_point *Q, size_t keylen)
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

	if (mbedtls_mpi_read_binary_le(&Q->MBEDTLS_PRIVATE(X), xb, keylen) == 0 &&
	    mbedtls_mpi_lset(&Q->MBEDTLS_PRIVATE(Z), 1) == 0)
		ret = 0;

out: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	jwt_freemem(xb);

	return ret;
}

/* @rfc{7518,4.6} ECDH-ES key agreement using the native MbedTLS EC key. On
 * encrypt an ephemeral keypair is generated on the recipient's curve, its "epk"
 * public half is written to @hdr, and the agreed key derived. On decrypt the
 * "epk" is read from @hdr. The derived key (CEK for ECDH-ES, KEK for +A*KW) is
 * returned in @dk. */
int mbedtls_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
			const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
			unsigned char **dk, size_t *dk_len)
{
	const mbedtls_jwk_t *jk = key->provider_data;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point eph_Q, peer_Q;
	mbedtls_mpi eph_d, z;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	unsigned char *apu = NULL, *apv = NULL, *out = NULL;
	unsigned char zbuf[66];
	int apu_len = 0, apv_len = 0, drbg_ok = 0, ret = 1;
	size_t z_len = 0, keydatalen = 0, fieldlen = 0;
	const char *algid = NULL, *crv = NULL;
	mbedtls_ecp_group_id gid;
	int is_okp;
	jwt_json_t *japu, *japv, *jepk;

	/* The recipient is an EC key (NIST) or an OKP X-curve key; both are held
	 * as a native ecp keypair. An OKP Ed-curve wrapper has no ecp keypair
	 * and is rejected (mbedtls has no Ed support anyway). */
	if (jk == NULL ||
	    (jk->kty != JWK_KEY_TYPE_EC &&
	     !(jk->kty == JWK_KEY_TYPE_OKP && !jk->okp_is_ed)))
		return 1; // LCOV_EXCL_LINE  (gating rejects non-ECDH keys first)

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&eph_Q);
	mbedtls_ecp_point_init(&peer_Q);
	mbedtls_mpi_init(&eph_d);
	mbedtls_mpi_init(&z);

	gid = mbedtls_ecp_keypair_get_group_id(&jk->ec);
	is_okp = gid_is_montgomery(gid);

	if (ecdh_keydatalen(alg, enc, &keydatalen, &algid))
		goto out; // LCOV_EXCL_LINE

	if (is_okp) {
		size_t keylen;
		if (okp_crv_info(gid, &keylen, &crv))
			goto out; // LCOV_EXCL_LINE
		fieldlen = keylen;
	} else {
		if (nist_crv_info(gid, &fieldlen, &crv))
			goto out; // LCOV_EXCL_LINE
	}

	if (mbedtls_ecp_group_load(&grp, gid))
		goto out; // LCOV_EXCL_LINE

	out = jwt_malloc(keydatalen);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (for_encrypt) {
		if (drbg_init(&entropy, &drbg))
			goto out; // LCOV_EXCL_LINE
		drbg_ok = 1;

		/* Ephemeral keypair on the recipient's curve. */
		if (mbedtls_ecdh_gen_public(&grp, &eph_d, &eph_Q,
					    mbedtls_ctr_drbg_random, &drbg))
			goto out; // LCOV_EXCL_LINE

		/* Z = ECDH(eph_priv, recipient_pub). */
		if (mbedtls_ecdh_compute_shared(&grp, &z,
				(mbedtls_ecp_point *)&jk->ec.MBEDTLS_PRIVATE(Q),
				&eph_d, mbedtls_ctr_drbg_random, &drbg))
			goto out; // LCOV_EXCL_LINE

		jepk = is_okp ? epk_okp_to_json(&eph_Q, crv, fieldlen)
			      : epk_ec_to_json(&eph_Q, crv, fieldlen);
		if (jepk == NULL)
			goto out; // LCOV_EXCL_LINE
		jwt_json_obj_set(hdr, "epk", jepk);
	} else {
		jepk = jwt_json_obj_get(hdr, "epk");
		if (jepk == NULL)
			goto out;
		if (is_okp) {
			if (epk_okp_from_json(jepk, crv, &peer_Q, fieldlen))
				goto out;
		} else {
			if (epk_ec_from_json(jepk, crv, &grp, &peer_Q, fieldlen))
				goto out;
		}

		if (drbg_init(&entropy, &drbg))
			goto out; // LCOV_EXCL_LINE
		drbg_ok = 1;

		/* Z = ECDH(recipient_priv, eph_pub). */
		if (mbedtls_ecdh_compute_shared(&grp, &z, &peer_Q,
				&jk->ec.MBEDTLS_PRIVATE(d),
				mbedtls_ctr_drbg_random, &drbg))
			goto out; // LCOV_EXCL_LINE
	}

	/* Z must be fixed field-length (left-padded). NIST Z is big-endian;
	 * X-curve Z is the raw little-endian shared secret. */
	z_len = fieldlen;
	if (is_okp) {
		if (mbedtls_mpi_write_binary_le(&z, zbuf, z_len))
			goto out; // LCOV_EXCL_LINE
	} else {
		if (mbedtls_mpi_write_binary(&z, zbuf, z_len))
			goto out; // LCOV_EXCL_LINE
	}

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
	if (drbg_ok)
		drbg_free(&entropy, &drbg);
	mbedtls_mpi_free(&eph_d);
	mbedtls_mpi_free(&z);
	mbedtls_ecp_point_free(&eph_Q);
	mbedtls_ecp_point_free(&peer_Q);
	mbedtls_ecp_group_free(&grp);

	return ret;
}
