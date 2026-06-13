/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-openssl.h"

#define GCM_TAG_LEN 16

/* @rfc{7516,5.1} CSPRNG for CEK/IV generation and the @rfc{7516,11.5}
 * random-CEK fallback. Backed by OpenSSL RAND_bytes. */
int openssl_rng(unsigned char *out, size_t len)
{
	if (out == NULL || len == 0)
		return 1; // LCOV_EXCL_LINE

	if (RAND_bytes(out, (int)len) != 1)
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* Map a GCM enc to its OpenSSL cipher. Returns NULL for non-GCM. */
static const EVP_CIPHER *gcm_cipher(jwe_enc_t enc)
{
	switch (enc) {
	case JWE_ENC_A128GCM:
		return EVP_aes_128_gcm();
	case JWE_ENC_A192GCM:
		return EVP_aes_192_gcm();
	case JWE_ENC_A256GCM:
		return EVP_aes_256_gcm();
	// LCOV_EXCL_START
	default:
		return NULL;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.3} AES GCM content encryption. */
int openssl_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	const EVP_CIPHER *cipher = gcm_cipher(enc);
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *out = NULL, *t = NULL;
	int len, ret = 1;

	if (cipher == NULL || cek_len != jwe_enc_cek_len(enc))
		return 1; // LCOV_EXCL_LINE

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE

	out = jwt_malloc(pt_len ? pt_len : 1);
	t = jwt_malloc(GCM_TAG_LEN);
	if (out == NULL || t == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				(int)iv_len, NULL) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptInit_ex(ctx, NULL, NULL, cek, iv) != 1)
		goto out; // LCOV_EXCL_LINE

	/* AAD */
	if (aad_len &&
	    EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptUpdate(ctx, out, &len, pt, (int)pt_len) != 1)
		goto out; // LCOV_EXCL_LINE
	*ct_len = len;

	if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1)
		goto out; // LCOV_EXCL_LINE
	*ct_len += len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, t) != 1)
		goto out; // LCOV_EXCL_LINE

	*ct = out;
	*tag = t;
	*tag_len = GCM_TAG_LEN;
	out = NULL;
	t = NULL;
	ret = 0;

out:
	jwt_freemem(out);
	jwt_freemem(t);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* @rfc{7518,5.3} AES GCM content decryption with tag verification. */
int openssl_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	const EVP_CIPHER *cipher = gcm_cipher(enc);
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *out = NULL;
	int len, ret = 1;

	if (cipher == NULL || cek_len != jwe_enc_cek_len(enc) ||
	    tag_len != GCM_TAG_LEN)
		return 1; // LCOV_EXCL_LINE

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE

	out = jwt_malloc(ct_len ? ct_len : 1);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				(int)iv_len, NULL) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, cek, iv) != 1)
		goto out; // LCOV_EXCL_LINE

	if (aad_len &&
	    EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto out; // LCOV_EXCL_LINE

	if (EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) != 1)
		goto out; // LCOV_EXCL_LINE
	*pt_len = len;

	/* Set the expected tag before finalizing. */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
				(void *)tag) != 1)
		goto out; // LCOV_EXCL_LINE

	/* EVP_DecryptFinal_ex returns <= 0 if the tag does not verify. This
	 * is the authentication check; a failure here means the ciphertext,
	 * AAD, IV, or tag was tampered with (or the CEK is wrong). */
	if (EVP_DecryptFinal_ex(ctx, out + len, &len) <= 0)
		goto out;
	*pt_len += len;

	*pt = out;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(out, ct_len ? ct_len : 1);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* @rfc{7518,5.2} Map a CBC-HMAC enc to its AES-CBC cipher, HMAC digest, and
 * the (equal) MAC/ENC key half-length, which is also the truncated tag length
 * T_LEN. Returns 0 on success. */
static int cbc_params(jwe_enc_t enc, const EVP_CIPHER **cipher,
		      const EVP_MD **md, size_t *half)
{
	switch (enc) {
	case JWE_ENC_A128CBC_HS256:
		*cipher = EVP_aes_128_cbc();
		*md = EVP_sha256();
		*half = 16;
		return 0;
	case JWE_ENC_A192CBC_HS384:
		*cipher = EVP_aes_192_cbc();
		*md = EVP_sha384();
		*half = 24;
		return 0;
	case JWE_ENC_A256CBC_HS512:
		*cipher = EVP_aes_256_cbc();
		*md = EVP_sha512();
		*half = 32;
		return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.2.2.1} Compute the authentication tag: HMAC over
 * AAD || IV || CT || AL, where AL is the 64-bit big-endian bit-length of the
 * AAD, truncated to the leftmost T_LEN (= half) octets. @out must hold at
 * least EVP_MAX_MD_SIZE bytes. */
static int cbc_hmac_tag(const EVP_MD *md, const unsigned char *mac_key,
			size_t half, const unsigned char *aad, size_t aad_len,
			const unsigned char *iv, size_t iv_len,
			const unsigned char *ct, size_t ct_len,
			unsigned char *out)
{
	unsigned char al[8];
	uint64_t aad_bits = (uint64_t)aad_len * 8;
	unsigned char *buf;
	size_t buf_len, off = 0;
	unsigned int mdlen = 0;
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

	if (HMAC(md, mac_key, (int)half, buf, buf_len, out, &mdlen) != NULL &&
	    mdlen >= half)
		ret = 0;

	jwt_freemem(buf);

	return ret;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content encryption (encrypt-then-MAC). */
int openssl_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	const EVP_CIPHER *cipher = NULL;
	const EVP_MD *md = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned char *out = NULL, *t = NULL;
	const unsigned char *mac_key, *enc_key;
	size_t half;
	int len, ret = 1;

	if (cbc_params(enc, &cipher, &md, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16)
		return 1; // LCOV_EXCL_LINE

	/* @rfc{7518,5.2.2.1} MAC_KEY is the first half, ENC_KEY the second. */
	mac_key = cek;
	enc_key = cek + half;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE

	/* CBC pads, so ciphertext can be up to pt_len + one block. */
	out = jwt_malloc(pt_len + EVP_CIPHER_block_size(cipher));
	t = jwt_malloc(half);
	if (out == NULL || t == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, enc_key, iv) != 1)
		goto out; // LCOV_EXCL_LINE
	if (EVP_EncryptUpdate(ctx, out, &len, pt, (int)pt_len) != 1)
		goto out; // LCOV_EXCL_LINE
	*ct_len = len;
	if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1)
		goto out; // LCOV_EXCL_LINE
	*ct_len += len;

	if (cbc_hmac_tag(md, mac_key, half, aad, aad_len, iv, iv_len,
			 out, *ct_len, hmac))
		goto out; // LCOV_EXCL_LINE
	memcpy(t, hmac, half);

	*ct = out;
	*tag = t;
	*tag_len = half;
	out = NULL;
	t = NULL;
	ret = 0;

out:
	jwt_freemem(out);
	jwt_freemem(t);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* @rfc{7518,5.2} AES-CBC + HMAC content decryption. Verifies the tag in
 * constant time BEFORE decrypting. */
int openssl_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	const EVP_CIPHER *cipher = NULL;
	const EVP_MD *md = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned char *out = NULL;
	const unsigned char *mac_key, *enc_key;
	size_t half;
	int len, ret = 1;

	if (cbc_params(enc, &cipher, &md, &half) ||
	    cek_len != jwe_enc_cek_len(enc) || iv_len != 16 ||
	    tag_len != half)
		return 1; // LCOV_EXCL_LINE

	mac_key = cek;
	enc_key = cek + half;

	/* @rfc{7518,5.2.2.2} Recompute and compare the tag in constant time
	 * before doing anything with the ciphertext. */
	if (cbc_hmac_tag(md, mac_key, half, aad, aad_len, iv, iv_len,
			 ct, ct_len, hmac))
		return 1; // LCOV_EXCL_LINE
	if (CRYPTO_memcmp(hmac, tag, half) != 0)
		return 1;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE

	out = jwt_malloc(ct_len ? ct_len : 1);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_DecryptInit_ex(ctx, cipher, NULL, enc_key, iv) != 1)
		goto out; // LCOV_EXCL_LINE
	if (EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) != 1)
		goto out; // LCOV_EXCL_LINE
	*pt_len = len;
	/* A bad final block (padding) fails here; the tag already authenticated
	 * the ciphertext, so this is an integrity failure too. */
	if (EVP_DecryptFinal_ex(ctx, out + len, &len) <= 0)
		goto out; // LCOV_EXCL_LINE
	*pt_len += len;

	*pt = out;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(out, ct_len ? ct_len : 1);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* Map an oct key length to the AES Key Wrap cipher (RFC 3394). */
static const EVP_CIPHER *kw_cipher(size_t key_len)
{
	switch (key_len) {
	case 16:
		return EVP_aes_128_wrap();
	case 24:
		return EVP_aes_192_wrap();
	case 32:
		return EVP_aes_256_wrap();
	// LCOV_EXCL_START
	default:
		return NULL;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,4.4} AES Key Wrap (RFC 3394) of the CEK. The wrapped output is
 * cek_len + 8 octets. */
int openssl_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
			size_t cek_len, unsigned char **out, size_t *out_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *buf = NULL;
	int len, ret = 1;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	cipher = kw_cipher(kek_len);
	/* AES-KW requires the CEK to be a multiple of 8 and at least 16. */
	if (cipher == NULL || cek_len < 16 || (cek_len % 8) != 0)
		return 1; // LCOV_EXCL_LINE

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE
	/* OpenSSL refuses wrap ciphers unless this flag is set. */
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	buf = jwt_malloc(cek_len + 8);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, kek, NULL) != 1)
		goto out; // LCOV_EXCL_LINE
	if (EVP_EncryptUpdate(ctx, buf, &len, cek, (int)cek_len) != 1)
		goto out; // LCOV_EXCL_LINE

	*out = buf;
	*out_len = len;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* @rfc{7518,4.4} AES Key Unwrap (RFC 3394). A failure here includes the
 * built-in integrity check failing (wrong KEK or tampered wrapped key). */
int openssl_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
			  size_t in_len, unsigned char **cek, size_t *cek_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *buf = NULL;
	int len, ret = 1;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	cipher = kw_cipher(kek_len);
	if (cipher == NULL || in_len < 24 || (in_len % 8) != 0)
		return 1;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	buf = jwt_malloc(in_len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_DecryptInit_ex(ctx, cipher, NULL, kek, NULL) != 1)
		goto out; // LCOV_EXCL_LINE
	/* Returns <= 0 if the RFC 3394 integrity check (the A6 IV) fails. */
	if (EVP_DecryptUpdate(ctx, buf, &len, in, (int)in_len) != 1)
		goto out;

	*cek = buf;
	*cek_len = len;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, in_len);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* Configure an RSA-OAEP EVP_PKEY_CTX for the given JWE alg. RSA-OAEP uses
 * SHA-1 + MGF1-SHA-1; RSA-OAEP-256 uses SHA-256 + MGF1-SHA-256. */
static int oaep_set_md(EVP_PKEY_CTX *pctx, jwe_key_alg_t alg)
{
	const EVP_MD *md;

	if (alg == JWE_ALG_RSA_OAEP)
		md = EVP_sha1();
	else if (alg == JWE_ALG_RSA_OAEP_256)
		md = EVP_sha256();
	else
		return 1; // LCOV_EXCL_LINE

	if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		return 1; // LCOV_EXCL_LINE
	if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md) <= 0)
		return 1; // LCOV_EXCL_LINE
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* @rfc{7518,4.3} RSAES-OAEP encryption of the CEK to the recipient public
 * key. The recipient's EVP_PKEY is the OpenSSL key parsed from the JWK. */
int openssl_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	EVP_PKEY *pkey = (EVP_PKEY *)key->provider_data;
	EVP_PKEY_CTX *pctx = NULL;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	int ret = 1;

	if (pkey == NULL)
		return 1; // LCOV_EXCL_LINE

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pctx == NULL)
		return 1; // LCOV_EXCL_LINE

	if (EVP_PKEY_encrypt_init(pctx) <= 0 || oaep_set_md(pctx, alg))
		goto out; // LCOV_EXCL_LINE

	if (EVP_PKEY_encrypt(pctx, NULL, &buflen, cek, cek_len) <= 0)
		goto out; // LCOV_EXCL_LINE

	buf = jwt_malloc(buflen);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_PKEY_encrypt(pctx, buf, &buflen, cek, cek_len) <= 0)
		goto out; // LCOV_EXCL_LINE

	*out = buf;
	*out_len = buflen;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	EVP_PKEY_CTX_free(pctx);

	return ret;
}

/* @rfc{7518,4.3} RSAES-OAEP decryption of the JWE Encrypted Key. A failure
 * here (wrong key, bad padding) is funnelled by the caller into the uniform
 * random-CEK path (RFC 7516 11.5). */
int openssl_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *in, size_t in_len,
			    unsigned char **cek, size_t *cek_len)
{
	EVP_PKEY *pkey = (EVP_PKEY *)key->provider_data;
	EVP_PKEY_CTX *pctx = NULL;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	int ret = 1;

	if (pkey == NULL)
		return 1; // LCOV_EXCL_LINE

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pctx == NULL)
		return 1; // LCOV_EXCL_LINE

	if (EVP_PKEY_decrypt_init(pctx) <= 0 || oaep_set_md(pctx, alg))
		goto out; // LCOV_EXCL_LINE

	if (EVP_PKEY_decrypt(pctx, NULL, &buflen, in, in_len) <= 0)
		goto out; // LCOV_EXCL_LINE

	buf = jwt_malloc(buflen ? buflen : 1);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	/* A decryption/padding failure returns <= 0 here. */
	if (EVP_PKEY_decrypt(pctx, buf, &buflen, in, in_len) <= 0)
		goto out;

	*cek = buf;
	*cek_len = buflen;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, buflen ? buflen : 1);
	EVP_PKEY_CTX_free(pctx);

	return ret;
}
