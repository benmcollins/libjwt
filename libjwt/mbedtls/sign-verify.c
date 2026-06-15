/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <psa/crypto.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

#include "jwt-mbedtls.h"

/* @rfc{7518,3.2} HMAC with SHA-2 via PSA. The oct key is imported as a volatile
 * PSA HMAC key, used once, and destroyed. */
static int mbedtls_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
                                 const char *str, unsigned int str_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t kid;
	psa_algorithm_t alg;
	size_t mac_size, mac_len = 0;
	psa_status_t st;

	*out = NULL;

	switch (jwt->alg) {
	case JWT_ALG_HS256:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_256); mac_size = 32; break;
	case JWT_ALG_HS384:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_384); mac_size = 48; break;
	case JWT_ALG_HS512:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_512); mac_size = 64; break;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, alg);

	if (psa_import_key(&attr, jwt->key->oct.key, jwt->key->oct.len, &kid))
		return 1; // LCOV_EXCL_LINE

	*out = jwt_malloc(mac_size);
	if (*out == NULL) {
		// LCOV_EXCL_START
		psa_destroy_key(kid);
		return 1;
		// LCOV_EXCL_STOP
	}

	st = psa_mac_compute(kid, alg, (const unsigned char *)str, str_len,
			     (unsigned char *)*out, mac_size, &mac_len);
	psa_destroy_key(kid);

	if (st != PSA_SUCCESS) {
		// LCOV_EXCL_START
		jwt_freemem(*out);
		return 1;
		// LCOV_EXCL_STOP
	}

	*len = (unsigned int)mac_len;

	return 0;
}

/* Map a JWS signing alg to its PSA signature algorithm (hash included). Returns
 * 0 on success. EdDSA is handled by the caller (rejected); HMAC never reaches
 * here. */
static int sign_alg_to_psa(jwt_alg_t alg, psa_algorithm_t *psa_alg)
{
	switch (alg) {
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		*psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256); return 0;
	case JWT_ALG_ES384:
		*psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384); return 0;
	case JWT_ALG_ES512:
		*psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_512); return 0;
	case JWT_ALG_RS256:
		*psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256); return 0;
	case JWT_ALG_RS384:
		*psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384); return 0;
	case JWT_ALG_RS512:
		*psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512); return 0;
	case JWT_ALG_PS256:
		*psa_alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256); return 0;
	case JWT_ALG_PS384:
		*psa_alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384); return 0;
	case JWT_ALG_PS512:
		*psa_alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512); return 0;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}
}

/* Sign using the native PSA key imported from the JWK material on the key
 * object. For ECDSA, PSA emits the raw R||S signature, which is exactly the
 * JOSE form; for RSA the PSS/PKCS#1v1.5 padding is selected by @alg. */
static int mbedtls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	const mbedtls_jwk_t *key;
	mbedtls_svc_key_id_t kid;
	psa_algorithm_t alg;
	unsigned char sig[PSA_SIGNATURE_MAX_SIZE];
	size_t sig_len = 0;

	*out = NULL;

	/* PSA here has no EdDSA; reject cleanly rather than mis-signing. */
	if (jwt->alg == JWT_ALG_EDDSA)
		return jwt_write_error(jwt,
			"JWT[MbedTLS]: MbedTLS does not support EdDSA");

	if (jwt->key == NULL ||
	    jwt->key->provider != JWT_CRYPTO_OPS_MBEDTLS ||
	    jwt->key->provider_data == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Key is not compatible"); // LCOV_EXCL_LINE

	key = jwt->key->provider_data;

	if (sign_alg_to_psa(jwt->alg, &alg))
		return jwt_write_error(jwt, "JWT[MbedTLS]: Unsupported algorithm"); // LCOV_EXCL_LINE

	if (mbedtls_jwk_to_psa(key, 1, alg, PSA_KEY_USAGE_SIGN_MESSAGE, &kid))
		return jwt_write_error(jwt, "JWT[MbedTLS]: Failed to load signing key"); // LCOV_EXCL_LINE

	if (psa_sign_message(kid, alg, (const unsigned char *)str, str_len,
			     sig, sizeof(sig), &sig_len)) {
		// LCOV_EXCL_START
		psa_destroy_key(kid);
		return jwt_write_error(jwt, "JWT[MbedTLS]: Error signing token");
		// LCOV_EXCL_STOP
	}
	psa_destroy_key(kid);

	*out = jwt_malloc(sig_len);
	if (*out == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Out of memory"); // LCOV_EXCL_LINE
	memcpy(*out, sig, sig_len);
	*len = (unsigned int)sig_len;

	return 0;
}

/* Verify using the native PSA key imported from the JWK material. */
static int mbedtls_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len,
				  unsigned char *sig, int sig_len)
{
	const mbedtls_jwk_t *key;
	mbedtls_svc_key_id_t kid;
	psa_algorithm_t alg;
	int exp_len = 0;

	/* PSA here has no EdDSA; reject cleanly. */
	if (jwt->alg == JWT_ALG_EDDSA)
		return jwt_write_error(jwt,
			"JWT[MbedTLS]: MbedTLS does not support EdDSA");

	if (jwt->key == NULL ||
	    jwt->key->provider != JWT_CRYPTO_OPS_MBEDTLS ||
	    jwt->key->provider_data == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Key is not compatible"); // LCOV_EXCL_LINE

	key = jwt->key->provider_data;

	if (sign_alg_to_psa(jwt->alg, &alg))
		return jwt_write_error(jwt, "JWT[MbedTLS]: Unsupported algorithm"); // LCOV_EXCL_LINE

	/* Require the signature to be exactly the size dictated by the bound
	 * algorithm: for EC the R||S length pinned to the curve (ES256/ES256K=64,
	 * ES384=96, ES512=132); for RSA exactly the modulus length. This matches
	 * the OpenSSL backend's stricter check. */
	if (key->kty == JWK_KEY_TYPE_EC) {
		switch (jwt->alg) {
		case JWT_ALG_ES256:
		case JWT_ALG_ES256K: exp_len = 64; break;
		case JWT_ALG_ES384: exp_len = 96; break;
		case JWT_ALG_ES512: exp_len = 132; break;
		// LCOV_EXCL_START
		default:
			return jwt_write_error(jwt,
				"JWT[MbedTLS]: Unexpected EC algorithm");
		// LCOV_EXCL_STOP
		}
		if (sig_len != exp_len)
			return jwt_write_error(jwt,
				"JWT[MbedTLS]: Invalid ECDSA sig size");
	} else if (key->kty == JWK_KEY_TYPE_RSA) {
		if (sig_len < 0 || (size_t)sig_len != (key->bits + 7) / 8)
			return jwt_write_error(jwt,
				"JWT[MbedTLS]: Invalid RSA signature size");
	} else {
		return jwt_write_error(jwt, "JWT[MbedTLS]: Unexpected key type"); // LCOV_EXCL_LINE
	}

	if (mbedtls_jwk_to_psa(key, 0, alg, PSA_KEY_USAGE_VERIFY_MESSAGE, &kid))
		return jwt_write_error(jwt, "JWT[MbedTLS]: Key is not compatible"); // LCOV_EXCL_LINE

	if (psa_verify_message(kid, alg, (const unsigned char *)head, head_len,
			       sig, (size_t)sig_len)) {
		psa_destroy_key(kid);
		return jwt_write_error(jwt, "JWT[MbedTLS]: Failed to verify signature");
	}
	psa_destroy_key(kid);

	return 0;
}

/* Export our ops */
struct jwt_crypto_ops jwt_mbedtls_ops = {
	.name			= "mbedtls",
	.provider		= JWT_CRYPTO_OPS_MBEDTLS,

	.sign_sha_hmac		= mbedtls_sign_sha_hmac,
	.sign_sha_pem		= mbedtls_sign_sha_pem,
	.verify_sha_pem		= mbedtls_verify_sha_pem,

	.jwk_implemented	= 1,
	.process_eddsa		= mbedtls_process_eddsa,
	.process_rsa		= mbedtls_process_rsa,
	.process_ec		= mbedtls_process_ec,
	.process_item_free	= mbedtls_process_item_free,
	/* Native-key -> JWK conversion is always done by OpenSSL. */
	.key2jwk		= openssl_key2jwk,

	.jwe_implemented	= 1,
	.rng			= mbedtls_rng,
	.encrypt_aes_gcm	= mbedtls_encrypt_aes_gcm,
	.decrypt_aes_gcm	= mbedtls_decrypt_aes_gcm,
	.encrypt_aes_cbc_hmac	= mbedtls_encrypt_aes_cbc_hmac,
	.decrypt_aes_cbc_hmac	= mbedtls_decrypt_aes_cbc_hmac,
	.wrap_aes_kw		= mbedtls_wrap_aes_kw,
	.unwrap_aes_kw		= mbedtls_unwrap_aes_kw,
	.wrap_aes_kw_raw	= mbedtls_wrap_aes_kw_raw,
	.unwrap_aes_kw_raw	= mbedtls_unwrap_aes_kw_raw,
	.encrypt_cek_rsa	= mbedtls_encrypt_cek_rsa,
	.decrypt_cek_rsa	= mbedtls_decrypt_cek_rsa,
	.ecdh_derive		= mbedtls_ecdh_derive,
};
