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
