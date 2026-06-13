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

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-openssl.h"

#define GCM_TAG_LEN 16

/* @rfc{7516,5.1} CSPRNG for CEK/IV generation and the @rfc{7516,11.5}
 * random-CEK fallback. Backed by OpenSSL RAND_bytes. */
int openssl_rng(unsigned char *out, size_t len)
{
	if (out == NULL || len == 0)
		return 1;

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
		return 1;

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
		return 1;

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
