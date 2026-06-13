/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

/* Is this a GCM content encryption algorithm? */
static int enc_is_gcm(jwe_enc_t enc)
{
	return enc == JWE_ENC_A128GCM || enc == JWE_ENC_A192GCM ||
	       enc == JWE_ENC_A256GCM;
}

/* Dispatch content encryption to the active backend for the given enc.
 * Returns 0 on success. */
int jwe_encrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	if (enc_is_gcm(enc)) {
		if (jwt_ops->encrypt_aes_gcm == NULL)
			return 1; // LCOV_EXCL_LINE
		return jwt_ops->encrypt_aes_gcm(enc, cek, cek_len, iv, iv_len,
			aad, aad_len, pt, pt_len, ct, ct_len, tag, tag_len);
	}

	if (jwt_ops->encrypt_aes_cbc_hmac == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->encrypt_aes_cbc_hmac(enc, cek, cek_len, iv, iv_len,
		aad, aad_len, pt, pt_len, ct, ct_len, tag, tag_len);
}

/* Dispatch content decryption (with tag verification) to the active backend. */
int jwe_decrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	if (enc_is_gcm(enc)) {
		if (jwt_ops->decrypt_aes_gcm == NULL)
			return 1; // LCOV_EXCL_LINE
		return jwt_ops->decrypt_aes_gcm(enc, cek, cek_len, iv, iv_len,
			aad, aad_len, ct, ct_len, tag, tag_len, pt, pt_len);
	}

	if (jwt_ops->decrypt_aes_cbc_hmac == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->decrypt_aes_cbc_hmac(enc, cek, cek_len, iv, iv_len,
		aad, aad_len, ct, ct_len, tag, tag_len, pt, pt_len);
}

/* @rfc{7516,11.4} @rfc{7517,4.2,4.3} Gate a JWK against a JWE key management
 * algorithm. */
const char *jwe_key_usage_check(const jwk_item_t *key, jwe_key_alg_t alg,
				int for_encrypt)
{
	jwk_key_type_t need = jwe_alg_required_kty(alg);

	/* Callers (setkey) already reject a NULL key; this is defensive. */
	if (key == NULL)
		return "JWE requires a key"; // LCOV_EXCL_LINE

	if (need == JWK_KEY_TYPE_NONE)
		return "Unknown JWE key management algorithm"; // LCOV_EXCL_LINE

	/* The key's actual type must match what the alg requires. This is the
	 * authoritative gate and does not depend on optional JWK hints. */
	if (jwks_item_kty(key) != need)
		return "Key type does not match JWE algorithm";

	/* @rfc{7517,4.2} If "use" is set, it must be "enc" for JWE; a key
	 * marked "sig" must never be used for encryption. */
	if (jwks_item_use(key) == JWK_PUB_KEY_USE_SIG)
		return "Key marked for signing cannot be used for JWE";

	/* @rfc{7517,4.3} If "key_ops" is present, it must permit the operation
	 * we are about to perform. dir/A*KW use (un)wrapKey; RSA-OAEP uses
	 * (en|de)crypt. If no key_ops are declared, this check is skipped. */
	if (jwks_item_key_ops(key) != JWK_KEY_OP_NONE) {
		jwk_key_op_t ops = jwks_item_key_ops(key);
		jwk_key_op_t want;

		switch (alg) {
		case JWE_ALG_DIR:
		case JWE_ALG_A128KW:
		case JWE_ALG_A192KW:
		case JWE_ALG_A256KW:
			want = for_encrypt ? JWK_KEY_OP_WRAP : JWK_KEY_OP_UNWRAP;
			break;
		case JWE_ALG_RSA_OAEP:
		case JWE_ALG_RSA_OAEP_256:
			want = for_encrypt ? JWK_KEY_OP_ENCRYPT
					   : JWK_KEY_OP_DECRYPT;
			break;
		// LCOV_EXCL_START
		default:
			return "Unknown JWE key management algorithm";
		// LCOV_EXCL_STOP
		}

		if (!(ops & want))
			return "Key does not permit the required JWE operation";
	}

	return NULL;
}
