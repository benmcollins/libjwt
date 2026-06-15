/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <mbedtls/md.h>
#include <mbedtls/ssl.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

#include "jwt-mbedtls.h"

static int mbedtls_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
                                 const char *str, unsigned int str_len)
{
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t *md_info;
	void *key;
	size_t key_len;
	int ret = 1;

	key = jwt->key->oct.key;
	key_len = jwt->key->oct.len;

	*out = NULL;

	/* Determine the HMAC algorithm based on jwt->alg */
	switch (jwt->alg) {
	case JWT_ALG_HS256:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;
	case JWT_ALG_HS384:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		break;
	case JWT_ALG_HS512:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		break;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	*out = jwt_malloc(mbedtls_md_get_size(md_info));
	if (*out == NULL)
		return 1; // LCOV_EXCL_LINE

	mbedtls_md_init(&ctx);

	ret = mbedtls_md_setup(&ctx, md_info, 1);
	if (ret) {
		// LCOV_EXCL_START
		mbedtls_md_free(&ctx);
		jwt_freemem(*out);
		return 1;
		// LCOV_EXCL_STOP
	}

	/* Start HMAC calculation */
	ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
	if (!ret)
		ret = mbedtls_md_hmac_update(&ctx, (const unsigned char *)str,
				       str_len);
	if (!ret)
		ret = mbedtls_md_hmac_finish(&ctx, (unsigned char *)*out);
	if (ret) {
		// LCOV_EXCL_START
		mbedtls_md_free(&ctx);
		jwt_freemem(*out);
		return 1;
		// LCOV_EXCL_STOP
	}

	/* Get the output size */
	*len = mbedtls_md_get_size(md_info);

	mbedtls_md_free(&ctx);

	return 0;
}

#define SIGN_ERROR(_msg) { jwt_write_error(jwt, "JWT[MbedTLS]: " _msg); goto sign_clean_key; }

/* Map a signing alg to its MbedTLS message digest. Returns NULL for algs that
 * do not use a PEM key here (HMAC) or are unsupported. */
static const mbedtls_md_info_t *sign_md_info(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_RS256:
	case JWT_ALG_PS256:
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	case JWT_ALG_RS384:
	case JWT_ALG_PS384:
	case JWT_ALG_ES384:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	case JWT_ALG_RS512:
	case JWT_ALG_PS512:
	case JWT_ALG_ES512:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	// LCOV_EXCL_START
	default:
		return NULL;
	// LCOV_EXCL_STOP
	}
}

/* Sign using the native MbedTLS key object stored on the JWK (provider_data),
 * not a re-parsed PEM. This is required for RSA-PSS, whose OpenSSL-exported
 * id-RSASSA-PSS PEM mbedtls_pk_parse_key rejects, and keeps every alg native. */
static int mbedtls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	size_t out_size;
	const mbedtls_md_info_t *md_info;
	const mbedtls_jwk_t *key;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	size_t sig_len = 0;
	const char *pers = "libjwt_ecdsa_sign";

	/* MbedTLS has no EdDSA; reject cleanly rather than mis-signing. */
	if (jwt->alg == JWT_ALG_EDDSA)
		return jwt_write_error(jwt,
			"JWT[MbedTLS]: MbedTLS does not support EdDSA");

	if (jwt->key == NULL ||
	    jwt->key->provider != JWT_CRYPTO_OPS_MBEDTLS ||
	    jwt->key->provider_data == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Key is not compatible"); // LCOV_EXCL_LINE

	key = jwt->key->provider_data;

	md_info = sign_md_info(jwt->alg);
	if (md_info == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Unsupported algorithm"); // LCOV_EXCL_LINE

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
			&entropy, (const unsigned char *)pers, strlen(pers)))
		SIGN_ERROR("Failed RNG setup"); // LCOV_EXCL_LINE

	/* Compute the hash of the input string */
	if (mbedtls_md(md_info, (unsigned char *)str, str_len, hash))
		SIGN_ERROR("Error initializing md context"); // LCOV_EXCL_LINE

	if (key->kty == JWK_KEY_TYPE_EC) {
		/* EC: produce a raw R||S JOSE signature. */
		mbedtls_ecp_keypair *kp = (mbedtls_ecp_keypair *)&key->ec;
		mbedtls_mpi r, s;
		int adj;

		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		if (mbedtls_ecdsa_sign(&kp->MBEDTLS_PRIVATE(grp), &r, &s,
				       &kp->MBEDTLS_PRIVATE(d), hash,
				       mbedtls_md_get_size(md_info),
				       mbedtls_ctr_drbg_random, &ctr_drbg)) {
			// LCOV_EXCL_START
			mbedtls_mpi_free(&r);
			mbedtls_mpi_free(&s);
			SIGN_ERROR("Error signing token");
			// LCOV_EXCL_STOP
		}

		switch (jwt->alg) {
		case JWT_ALG_ES256:
		case JWT_ALG_ES256K:
			adj = 32;
			break;
		case JWT_ALG_ES384:
			adj = 48;
			break;
		case JWT_ALG_ES512:
			adj = 66;
			break;
		// LCOV_EXCL_START
		default:
			mbedtls_mpi_free(&r);
			mbedtls_mpi_free(&s);
			SIGN_ERROR("Unknown EC alg");
		// LCOV_EXCL_STOP
		}

		out_size = adj * 2;
		*out = jwt_malloc(out_size);
		if (*out == NULL) {
			// LCOV_EXCL_START
			mbedtls_mpi_free(&r);
			mbedtls_mpi_free(&s);
			SIGN_ERROR("Out of memory");
			// LCOV_EXCL_STOP
		}
		memset(*out, 0, out_size);

		mbedtls_mpi_write_binary(&r, (unsigned char *)(*out), adj);
		mbedtls_mpi_write_binary(&s, (unsigned char *)(*out) + adj, adj);

		*len = out_size;

		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);
	} else if (key->kty == JWK_KEY_TYPE_RSA) {
		mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)&key->rsa;

		switch (jwt->alg) {
		case JWT_ALG_PS256:
		case JWT_ALG_PS384:
		case JWT_ALG_PS512:
			if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21,
					mbedtls_md_get_type(md_info)))
				SIGN_ERROR("Failed setting RSASSA-PSS padding"); // LCOV_EXCL_LINE

			if (mbedtls_rsa_rsassa_pss_sign(rsa,
					mbedtls_ctr_drbg_random, &ctr_drbg,
					mbedtls_md_get_type(md_info),
					mbedtls_md_get_size(md_info), hash, sig))
				SIGN_ERROR("Failed signing RSASSA-PSS"); // LCOV_EXCL_LINE
			break;

		case JWT_ALG_RS256:
		case JWT_ALG_RS384:
		case JWT_ALG_RS512:
			/* Reset the shared context to PKCS1v1.5 padding: a prior
			 * PSS or RSA-OAEP op on the same key object leaves it at
			 * PKCS_V21, and the v1.5 signer rejects that state
			 * (MBEDTLS_ERR_RSA_BAD_INPUT_DATA). */
			if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15,
						    MBEDTLS_MD_NONE))
				SIGN_ERROR("Failed setting PKCS1 padding"); // LCOV_EXCL_LINE
			if (mbedtls_rsa_rsassa_pkcs1_v15_sign(rsa,
					mbedtls_ctr_drbg_random, &ctr_drbg,
					mbedtls_md_get_type(md_info),
					mbedtls_md_get_size(md_info), hash, sig))
				SIGN_ERROR("Error signing token"); // LCOV_EXCL_LINE
			break;

		// LCOV_EXCL_START
		default:
			SIGN_ERROR("Unexpected algorithm");
		// LCOV_EXCL_STOP
		}

		sig_len = mbedtls_rsa_get_len(rsa);

		*out = jwt_malloc(sig_len);
		if (*out == NULL)
			SIGN_ERROR("Out of memory"); // LCOV_EXCL_LINE
		memcpy(*out, sig, sig_len);
		*len = sig_len;
	} else {
		SIGN_ERROR("Key is not compatible"); // LCOV_EXCL_LINE
	}

sign_clean_key:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return jwt->error;
}

#define VERIFY_ERROR(_msg) { jwt_write_error(jwt, "JWT[MbedTLS]: " _msg); goto verify_clean_key; }

/* Verify using the native MbedTLS key object on the JWK (provider_data). */
static int mbedtls_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len,
				  unsigned char *sig, int sig_len)
{
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info = NULL;
	const mbedtls_jwk_t *key;
	int ret = 1;

	/* MbedTLS has no EdDSA; reject cleanly. */
	if (jwt->alg == JWT_ALG_EDDSA)
		return jwt_write_error(jwt,
			"JWT[MbedTLS]: MbedTLS does not support EdDSA");

	if (jwt->key == NULL ||
	    jwt->key->provider != JWT_CRYPTO_OPS_MBEDTLS ||
	    jwt->key->provider_data == NULL)
		return jwt_write_error(jwt, "JWT[MbedTLS]: Key is not compatible"); // LCOV_EXCL_LINE

	key = jwt->key->provider_data;

	md_info = sign_md_info(jwt->alg);
	if (md_info == NULL)
		VERIFY_ERROR("Unsupported algorithm"); // LCOV_EXCL_LINE

	/* Compute the hash of the input string */
	if ((ret = mbedtls_md(md_info, (const unsigned char *)head, head_len,
			      hash)))
		VERIFY_ERROR("Failed to compute hash"); // LCOV_EXCL_LINE

	if (key->kty == JWK_KEY_TYPE_EC) {
		mbedtls_ecp_keypair *kp = (mbedtls_ecp_keypair *)&key->ec;
		mbedtls_mpi r, s;
		int exp_len;

		/* Require the signature to be exactly the size dictated by the
		 * bound algorithm, not merely one of the three valid ECDSA sizes.
		 * This pins R||S to the alg/curve (ES256/ES256K=64, ES384=96,
		 * ES512=132), matching the OpenSSL backend's stricter check. */
		switch (jwt->alg) {
		case JWT_ALG_ES256:
		case JWT_ALG_ES256K:
			exp_len = 64;
			break;
		case JWT_ALG_ES384:
			exp_len = 96;
			break;
		case JWT_ALG_ES512:
			exp_len = 132;
			break;
		// LCOV_EXCL_START
		default:
			VERIFY_ERROR("Unexpected EC algorithm");
		// LCOV_EXCL_STOP
		}

		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		/* Split R/S from the JOSE signature. */
		if (sig_len == exp_len) {
			size_t r_size = sig_len / 2;
			mbedtls_mpi_read_binary(&r, sig, r_size);
			mbedtls_mpi_read_binary(&s, sig + r_size, r_size);
		} else {
			mbedtls_mpi_free(&r);
			mbedtls_mpi_free(&s);
			VERIFY_ERROR("Invalid ECDSA sig size");
		}

		if (mbedtls_ecdsa_verify(&kp->MBEDTLS_PRIVATE(grp), hash,
				mbedtls_md_get_size(md_info),
				&kp->MBEDTLS_PRIVATE(Q), &r, &s))
			ret = 1;

		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);

		if (ret)
			VERIFY_ERROR("Failed to verify signature");
	} else if (key->kty == JWK_KEY_TYPE_RSA) {
		mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)&key->rsa;

		/* The MbedTLS RSA verify functions take no length argument and
		 * unconditionally read mbedtls_rsa_get_len(rsa) bytes from sig.
		 * Reject a signature that is not exactly the modulus length so a
		 * short attacker-controlled segment cannot cause an out-of-bounds
		 * read of the heap buffer (which is sized to the decoded length). */
		if (sig_len < 0 || (size_t)sig_len != mbedtls_rsa_get_len(rsa))
			VERIFY_ERROR("Invalid RSA signature size");

		if (jwt->alg == JWT_ALG_PS256 || jwt->alg == JWT_ALG_PS384 ||
		    jwt->alg == JWT_ALG_PS512) {
			if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21,
					mbedtls_md_get_type(md_info)))
				VERIFY_ERROR("Failed setting RSASSA-PSS padding"); // LCOV_EXCL_LINE
			if (mbedtls_rsa_rsassa_pss_verify(rsa,
					mbedtls_md_get_type(md_info),
					mbedtls_md_get_size(md_info),
					hash, sig))
				VERIFY_ERROR("Failed to verify signature");
		} else {
			/* Reset to PKCS1v1.5 padding before verifying (see the
			 * matching note in the sign path). */
			if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15,
						    MBEDTLS_MD_NONE))
				VERIFY_ERROR("Failed setting PKCS1 padding"); // LCOV_EXCL_LINE
			if (mbedtls_rsa_rsassa_pkcs1_v15_verify(rsa,
					mbedtls_md_get_type(md_info),
					mbedtls_md_get_size(md_info),
					hash, sig))
				VERIFY_ERROR("Failed to verify signature");
		}
	} else {
		VERIFY_ERROR("Unexpected key type"); // LCOV_EXCL_LINE
	}

	ret = 0;

verify_clean_key:
	return jwt->error;
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
