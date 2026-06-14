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
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

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

/* @rfc{7518,4.4} AES Key Wrap (RFC 3394) with a raw KEK. The wrapped output
 * is in_len + 8 octets. */
static int kw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *in, size_t in_len,
		       unsigned char **out, size_t *out_len)
{
	const EVP_CIPHER *cipher = kw_cipher(kek_len);
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *buf = NULL;
	int len, ret = 1;

	/* AES-KW requires the wrapped data to be a multiple of 8 and >= 16. */
	if (cipher == NULL || in_len < 16 || (in_len % 8) != 0)
		return 1; // LCOV_EXCL_LINE

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 1; // LCOV_EXCL_LINE
	/* OpenSSL refuses wrap ciphers unless this flag is set. */
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	buf = jwt_malloc(in_len + 8);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, kek, NULL) != 1)
		goto out; // LCOV_EXCL_LINE
	if (EVP_EncryptUpdate(ctx, buf, &len, in, (int)in_len) != 1)
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

/* @rfc{7518,4.4} AES Key Unwrap (RFC 3394) with a raw KEK. */
static int kw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **out, size_t *out_len)
{
	const EVP_CIPHER *cipher = kw_cipher(kek_len);
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *buf = NULL;
	int len, ret = 1;

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

	*out = buf;
	*out_len = len;
	buf = NULL;
	ret = 0;

out:
	jwt_freemem(buf);
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* @rfc{7518,4.4} AES Key Wrap of the CEK with the recipient's oct key. */
int openssl_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
			size_t cek_len, unsigned char **out, size_t *out_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

/* @rfc{7518,4.4} AES Key Unwrap with the recipient's oct key. */
int openssl_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
			  size_t in_len, unsigned char **cek, size_t *cek_len)
{
	const unsigned char *kek;
	size_t kek_len = 0;

	if (jwks_item_key_oct(key, &kek, &kek_len))
		return 1; // LCOV_EXCL_LINE

	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
}

/* @rfc{7518,4.4} AES Key Wrap / Unwrap with a raw KEK (used by ECDH-ES+A*KW,
 * where the KEK is the agreed key rather than a JWK). */
int openssl_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	return kw_wrap_raw(kek, kek_len, cek, cek_len, out, out_len);
}

int openssl_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
			      const unsigned char *in, size_t in_len,
			      unsigned char **cek, size_t *cek_len)
{
	return kw_unwrap_raw(kek, kek_len, in, in_len, cek, cek_len);
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

/* @rfc{7518,4.3} RSAES-OAEP encrypt the CEK to a recipient EVP_PKEY. Shared by
 * the OpenSSL op (which uses the EVP_PKEY on the JWK) and the GnuTLS fallback
 * (GnuTLS cannot OAEP-encrypt with a public-only key, so it builds an EVP_PKEY
 * from the JWK's public PEM and calls this). */
static int rsa_oaep_encrypt_pkey(jwe_key_alg_t alg, EVP_PKEY *pkey,
				 const unsigned char *cek, size_t cek_len,
				 unsigned char **out, size_t *out_len)
{
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

/* @rfc{7518,4.3} RSAES-OAEP encryption of the CEK. The recipient's EVP_PKEY is
 * the OpenSSL key parsed from the JWK. */
int openssl_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *cek, size_t cek_len,
			    unsigned char **out, size_t *out_len)
{
	return rsa_oaep_encrypt_pkey(alg, (EVP_PKEY *)key->provider_data,
				     cek, cek_len, out, out_len);
}

/* RSAES-OAEP encryption from a PEM-encoded RSA public key. Used by the GnuTLS
 * backend, whose pubkey path cannot OAEP-encrypt natively. */
int openssl_encrypt_cek_rsa_pem(jwe_key_alg_t alg, const char *pem,
				const unsigned char *cek, size_t cek_len,
				unsigned char **out, size_t *out_len)
{
	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;
	int ret = 1;

	if (pem == NULL)
		return 1; // LCOV_EXCL_LINE

	bio = BIO_new_mem_buf(pem, -1);
	if (bio == NULL)
		return 1; // LCOV_EXCL_LINE

	/* The convenience PEM is a public key for a public-only JWK and a
	 * private key for a private JWK; both carry the public part needed to
	 * encrypt. Try public first, then private. */
	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (pkey == NULL) {
		BIO_free(bio);
		bio = BIO_new_mem_buf(pem, -1);
		if (bio == NULL)
			return 1; // LCOV_EXCL_LINE
		pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	}

	if (pkey != NULL)
		ret = rsa_oaep_encrypt_pkey(alg, pkey, cek, cek_len, out,
					    out_len);

	EVP_PKEY_free(pkey);
	BIO_free(bio);

	return ret;
}

/* @rfc{7518,4.3} RSAES-OAEP decrypt with a recipient private EVP_PKEY. Shared
 * by the OpenSSL op and the GnuTLS fallback (see rsa_oaep_encrypt_pkey). */
static int rsa_oaep_decrypt_pkey(jwe_key_alg_t alg, EVP_PKEY *pkey,
				 const unsigned char *in, size_t in_len,
				 unsigned char **cek, size_t *cek_len)
{
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

/* @rfc{7518,4.3} RSAES-OAEP decryption of the JWE Encrypted Key. A failure
 * here (wrong key, bad padding) is funnelled by the caller into the uniform
 * random-CEK path (RFC 7516 11.5). */
int openssl_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
			    const unsigned char *in, size_t in_len,
			    unsigned char **cek, size_t *cek_len)
{
	return rsa_oaep_decrypt_pkey(alg, (EVP_PKEY *)key->provider_data,
				     in, in_len, cek, cek_len);
}

/* RSAES-OAEP decryption from a PEM-encoded RSA private key. Used by the GnuTLS
 * backend, whose native OAEP decrypt is unreliable on the supported versions. */
int openssl_decrypt_cek_rsa_pem(jwe_key_alg_t alg, const char *pem,
				const unsigned char *in, size_t in_len,
				unsigned char **cek, size_t *cek_len)
{
	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;
	int ret = 1;

	if (pem == NULL)
		return 1; // LCOV_EXCL_LINE

	bio = BIO_new_mem_buf(pem, -1);
	if (bio == NULL)
		return 1; // LCOV_EXCL_LINE

	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (pkey != NULL)
		ret = rsa_oaep_decrypt_pkey(alg, pkey, in, in_len, cek, cek_len);

	EVP_PKEY_free(pkey);
	BIO_free(bio);

	return ret;
}

/* ======================== ECDH-ES (RFC 7518 4.6) ======================== */

/* The derived-key length (octets) and the ASCII AlgorithmID for the Concat
 * KDF. For ECDH-ES (Direct), the AlgorithmID is the "enc" value and the
 * length is the enc CEK length. For ECDH-ES+A*KW, the AlgorithmID is the
 * "alg" value and the length is the AES-KW key size. */
static int ecdh_keydatalen(jwe_key_alg_t alg, jwe_enc_t enc,
			   size_t *len, const char **algid)
{
	switch (alg) {
	case JWE_ALG_ECDH_ES:
		/* Direct: the AlgorithmID is "enc" and the agreed key is the
		 * CEK of the content algorithm's length. */
		*len = jwe_enc_cek_len(enc);
		*algid = jwe_enc_str(enc);
		return (*len && *algid) ? 0 : 1;
	/* +A*KW: the AlgorithmID is "alg" and the agreed key is the KEK that
	 * wraps the CEK (the AES key size of the named wrap). */
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

/* @rfc{7518,4.6.2} Concat KDF (NIST SP 800-56A 5.8.1) with SHA-256. JWE only
 * ever needs <= 32 octets (one SHA-256 block), so a single round suffices.
 * OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, each
 * length-prefixed; SuppPubInfo is the keydatalen in bits (32-bit BE). */
static int concat_kdf(const unsigned char *z, size_t z_len,
		      const char *algid, const unsigned char *apu, size_t apu_len,
		      const unsigned char *apv, size_t apv_len,
		      size_t keydatalen, unsigned char *out)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *buf;
	size_t algid_len = strlen(algid);
	size_t buf_len, off = 0;
	uint32_t bits = (uint32_t)(keydatalen * 8);
	EVP_MD_CTX *mdctx = NULL;
	unsigned char counter[4] = { 0, 0, 0, 1 };
	unsigned char supppub[4];
	unsigned int hlen = 0;
	int ret = 1;

	if (keydatalen > SHA256_DIGEST_LENGTH)
		return 1; // LCOV_EXCL_LINE

	supppub[0] = (unsigned char)((bits >> 24) & 0xff);
	supppub[1] = (unsigned char)((bits >> 16) & 0xff);
	supppub[2] = (unsigned char)((bits >> 8) & 0xff);
	supppub[3] = (unsigned char)(bits & 0xff);

	/* counter || Z || OtherInfo */
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

	mdctx = EVP_MD_CTX_new();
	if (mdctx != NULL &&
	    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(mdctx, buf, off) == 1 &&
	    EVP_DigestFinal_ex(mdctx, hash, &hlen) == 1) {
		memcpy(out, hash, keydatalen);
		ret = 0;
	}

	EVP_MD_CTX_free(mdctx);
	jwt_scrub_and_free(buf, buf_len);

	return ret;
}

/* Build an "epk" JWK object {kty,crv,x,y} from an EC public EVP_PKEY. */
static jwt_json_t *epk_to_json(EVP_PKEY *pkey, const char *crv)
{
	jwt_json_t *epk = NULL;
	char_auto *x_b64 = NULL, *y_b64 = NULL;
	unsigned char *xb = NULL, *yb = NULL;
	BIGNUM *x = NULL, *y = NULL;
	size_t fieldlen;
	int xlen, ylen;

	/* Coordinate size in octets from the curve. */
	if (!strcmp(crv, "P-256"))
		fieldlen = 32;
	else if (!strcmp(crv, "P-384"))
		fieldlen = 48;
	else if (!strcmp(crv, "P-521"))
		fieldlen = 66;
	else
		return NULL; // LCOV_EXCL_LINE

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1)
		goto out; // LCOV_EXCL_LINE

	xb = jwt_malloc(fieldlen);
	yb = jwt_malloc(fieldlen);
	if (xb == NULL || yb == NULL)
		goto out; // LCOV_EXCL_LINE

	/* Left-pad to the fixed field length (BN_bn2binpad). */
	if (BN_bn2binpad(x, xb, (int)fieldlen) < 0 ||
	    BN_bn2binpad(y, yb, (int)fieldlen) < 0)
		goto out; // LCOV_EXCL_LINE

	xlen = jwt_base64uri_encode(&x_b64, (char *)xb, (int)fieldlen);
	ylen = jwt_base64uri_encode(&y_b64, (char *)yb, (int)fieldlen);
	if (xlen <= 0 || ylen <= 0)
		goto out; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		goto out; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str("EC"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));
	jwt_json_obj_set(epk, "y", jwt_json_create_str(y_b64));

out:
	BN_free(x);
	BN_free(y);
	jwt_freemem(xb);
	jwt_freemem(yb);

	return epk;
}

/* Build a public-key EVP_PKEY from an "epk" JWK object. The crv must match
 * the recipient's. */
static EVP_PKEY *epk_from_json(jwt_json_t *epk, const char *want_crv)
{
	jwt_json_t *jkty, *jcrv, *jx, *jy;
	const char *kty, *crv, *ossl_crv;
	unsigned char *xb = NULL, *yb = NULL, *point = NULL;
	int xlen = 0, ylen = 0;
	size_t fieldlen, ptlen;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY *pkey = NULL;

	jkty = jwt_json_obj_get(epk, "kty");
	jcrv = jwt_json_obj_get(epk, "crv");
	jx = jwt_json_obj_get(epk, "x");
	jy = jwt_json_obj_get(epk, "y");
	if (!jkty || !jcrv || !jx || !jy || !jwt_json_is_string(jkty) ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx) ||
	    !jwt_json_is_string(jy))
		return NULL; // LCOV_EXCL_LINE

	kty = jwt_json_str_val(jkty);
	crv = jwt_json_str_val(jcrv);
	if (strcmp(kty, "EC") || strcmp(crv, want_crv))
		return NULL;

	if (!strcmp(crv, "P-256"))
		{ fieldlen = 32; ossl_crv = "prime256v1"; }
	else if (!strcmp(crv, "P-384"))
		{ fieldlen = 48; ossl_crv = "secp384r1"; }
	else if (!strcmp(crv, "P-521"))
		{ fieldlen = 66; ossl_crv = "secp521r1"; }
	else
		return NULL; // LCOV_EXCL_LINE

	xb = jwt_base64uri_decode(jwt_json_str_val(jx), &xlen);
	yb = jwt_base64uri_decode(jwt_json_str_val(jy), &ylen);
	if (xb == NULL || yb == NULL || (size_t)xlen != fieldlen ||
	    (size_t)ylen != fieldlen)
		goto out; // LCOV_EXCL_LINE

	/* Uncompressed point: 0x04 || X || Y */
	ptlen = 1 + fieldlen * 2;
	point = jwt_malloc(ptlen);
	if (point == NULL)
		goto out; // LCOV_EXCL_LINE
	point[0] = 0x04;
	memcpy(point + 1, xb, fieldlen);
	memcpy(point + 1 + fieldlen, yb, fieldlen);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		goto out; // LCOV_EXCL_LINE
	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					ossl_crv, 0);
	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					 point, ptlen);
	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL)
		goto out; // LCOV_EXCL_LINE

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL || EVP_PKEY_fromdata_init(pctx) <= 0 ||
	    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
		pkey = NULL; // LCOV_EXCL_LINE

out:
	jwt_freemem(xb);
	jwt_freemem(yb);
	jwt_freemem(point);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(pctx);

	return pkey;
}

/* Is this an OKP X-curve (X25519/X448) usable for ECDH? */
static int crv_is_okp_x(const char *crv)
{
	return !strcmp(crv, "X25519") || !strcmp(crv, "X448");
}

/* Build an "epk" JWK object {kty:"OKP",crv,x} from an OKP public EVP_PKEY.
 * OKP public keys are a single raw octet string, base64url'd as "x". */
static jwt_json_t *okp_epk_to_json(EVP_PKEY *pkey, const char *crv)
{
	jwt_json_t *epk = NULL;
	char_auto *x_b64 = NULL;
	unsigned char *raw = NULL;
	size_t rawlen = 0;

	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &rawlen) != 1)
		return NULL; // LCOV_EXCL_LINE
	raw = jwt_malloc(rawlen);
	if (raw == NULL)
		return NULL; // LCOV_EXCL_LINE
	if (EVP_PKEY_get_raw_public_key(pkey, raw, &rawlen) != 1)
		goto out; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&x_b64, (char *)raw, (int)rawlen) <= 0)
		goto out; // LCOV_EXCL_LINE

	epk = jwt_json_create();
	if (epk == NULL)
		goto out; // LCOV_EXCL_LINE
	jwt_json_obj_set(epk, "kty", jwt_json_create_str("OKP"));
	jwt_json_obj_set(epk, "crv", jwt_json_create_str(crv));
	jwt_json_obj_set(epk, "x", jwt_json_create_str(x_b64));

out:
	jwt_freemem(raw);

	return epk;
}

/* Build a public OKP EVP_PKEY from an "epk" JWK object. */
static EVP_PKEY *okp_epk_from_json(jwt_json_t *epk, const char *want_crv)
{
	jwt_json_t *jkty, *jcrv, *jx;
	const char *kty, *crv;
	unsigned char *xb = NULL;
	int xlen = 0;
	EVP_PKEY *pkey = NULL;

	jkty = jwt_json_obj_get(epk, "kty");
	jcrv = jwt_json_obj_get(epk, "crv");
	jx = jwt_json_obj_get(epk, "x");
	if (!jkty || !jcrv || !jx || !jwt_json_is_string(jkty) ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx))
		return NULL; // LCOV_EXCL_LINE

	kty = jwt_json_str_val(jkty);
	crv = jwt_json_str_val(jcrv);
	if (strcmp(kty, "OKP") || strcmp(crv, want_crv))
		return NULL;

	xb = jwt_base64uri_decode(jwt_json_str_val(jx), &xlen);
	if (xb == NULL || xlen <= 0)
		goto out; // LCOV_EXCL_LINE

	pkey = EVP_PKEY_new_raw_public_key_ex(NULL, want_crv, NULL, xb,
					      (size_t)xlen);

out:
	jwt_freemem(xb);

	return pkey;
}

/* Raw ECDH shared secret Z between a private and a peer public EVP_PKEY. */
static int ecdh_z(EVP_PKEY *priv, EVP_PKEY *peer, unsigned char **z,
		  size_t *z_len)
{
	EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(priv, NULL);
	unsigned char *buf = NULL;
	size_t len = 0;
	int ret = 1;

	if (dctx == NULL)
		return 1; // LCOV_EXCL_LINE

	if (EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, peer) <= 0 ||
	    EVP_PKEY_derive(dctx, NULL, &len) <= 0)
		goto out; // LCOV_EXCL_LINE

	buf = jwt_malloc(len);
	if (buf == NULL)
		goto out; // LCOV_EXCL_LINE

	if (EVP_PKEY_derive(dctx, buf, &len) <= 0)
		goto out; // LCOV_EXCL_LINE

	*z = buf;
	*z_len = len;
	buf = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(buf, len);
	EVP_PKEY_CTX_free(dctx);

	return ret;
}

/* @rfc{7518,4.6} ECDH-ES key agreement. On encrypt (for_encrypt=1) an
 * ephemeral keypair is generated on the recipient's curve, the "epk" public
 * half is written to @hdr, and the agreed key is derived. On decrypt the
 * "epk" is read from @hdr. @apu/@apv (base64url) are read from @hdr if
 * present. The derived key (CEK for ECDH-ES, KEK for ECDH-ES+A*KW) is
 * returned in @dk. */
int openssl_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
			const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
			unsigned char **dk, size_t *dk_len)
{
	EVP_PKEY *stat = (EVP_PKEY *)key->provider_data;
	EVP_PKEY *eph = NULL, *peer = NULL;
	EVP_PKEY_CTX *gctx = NULL;
	unsigned char *z = NULL, *apu = NULL, *apv = NULL, *out = NULL;
	int apu_len = 0, apv_len = 0;
	size_t z_len = 0, keydatalen = 0;
	const char *algid = NULL;
	const char *crv = key->curve;
	jwt_json_t *japu, *japv, *jepk;
	int ret = 1;

	if (stat == NULL || crv[0] == '\0')
		return 1; // LCOV_EXCL_LINE

	if (ecdh_keydatalen(alg, enc, &keydatalen, &algid))
		return 1; // LCOV_EXCL_LINE

	out = jwt_malloc(keydatalen);
	if (out == NULL)
		goto out; // LCOV_EXCL_LINE

	int is_okp = crv_is_okp_x(crv);

	if (for_encrypt) {
		/* Ephemeral keypair on the recipient's curve. OKP curves
		 * (X25519/X448) keygen directly by name; EC needs the group
		 * set on the context. */
		if (is_okp) {
			gctx = EVP_PKEY_CTX_new_from_name(NULL, crv, NULL);
			if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0)
				goto out; // LCOV_EXCL_LINE
		} else {
			const char *ossl_crv = crv;

			if (!strcmp(crv, "P-256")) ossl_crv = "prime256v1";
			else if (!strcmp(crv, "P-384")) ossl_crv = "secp384r1";
			else if (!strcmp(crv, "P-521")) ossl_crv = "secp521r1";
			else goto out;

			gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
			if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0)
				goto out; // LCOV_EXCL_LINE
			if (EVP_PKEY_CTX_set_group_name(gctx, ossl_crv) <= 0)
				goto out; // LCOV_EXCL_LINE
		}
		if (EVP_PKEY_keygen(gctx, &eph) <= 0)
			goto out; // LCOV_EXCL_LINE

		/* Z = ECDH(eph_priv, recipient_pub). */
		if (ecdh_z(eph, stat, &z, &z_len))
			goto out; // LCOV_EXCL_LINE

		/* Emit the epk public half in the header. */
		jepk = is_okp ? okp_epk_to_json(eph, crv)
			      : epk_to_json(eph, crv);
		if (jepk == NULL)
			goto out; // LCOV_EXCL_LINE
		jwt_json_obj_set(hdr, "epk", jepk);
	} else {
		jepk = jwt_json_obj_get(hdr, "epk");
		if (jepk == NULL)
			goto out;
		peer = is_okp ? okp_epk_from_json(jepk, crv)
			      : epk_from_json(jepk, crv);
		if (peer == NULL)
			goto out;
		/* Z = ECDH(recipient_priv, eph_pub). */
		if (ecdh_z(stat, peer, &z, &z_len))
			goto out; // LCOV_EXCL_LINE
	}

	/* apu/apv (optional PartyU/PartyV info) — fed to the Concat KDF as-is.
	 * (the builder emits them via jwe_builder_set_partyinfo). */
	japu = jwt_json_obj_get(hdr, "apu");
	if (japu && jwt_json_is_string(japu))
		apu = jwt_base64uri_decode(jwt_json_str_val(japu), &apu_len);
	japv = jwt_json_obj_get(hdr, "apv");
	if (japv && jwt_json_is_string(japv))
		apv = jwt_base64uri_decode(jwt_json_str_val(japv), &apv_len);

	if (concat_kdf(z, z_len, algid, apu, apu_len < 0 ? 0 : (size_t)apu_len,
		       apv, apv_len < 0 ? 0 : (size_t)apv_len, keydatalen, out))
		goto out; // LCOV_EXCL_LINE

	*dk = out;
	*dk_len = keydatalen;
	out = NULL;
	ret = 0;

out:
	jwt_scrub_and_free(z, z_len);
	jwt_freemem(apu);
	jwt_freemem(apv);
	jwt_scrub_and_free(out, keydatalen);
	EVP_PKEY_free(eph);
	EVP_PKEY_free(peer);
	EVP_PKEY_CTX_free(gctx);

	return ret;
}
