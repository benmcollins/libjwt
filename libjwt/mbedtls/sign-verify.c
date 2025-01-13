/* Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <mbedtls/md.h>
#include <mbedtls/ssl.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
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

	if (!ops_compat(jwt->key, JWT_CRYPTO_OPS_MBEDTLS))
		return 1;

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
	default:
		return 1;
	}

	*out = jwt_malloc(mbedtls_md_get_size(md_info));
	if (*out == NULL)
		return 1;

	mbedtls_md_init(&ctx);

	ret = mbedtls_md_setup(&ctx, md_info, 1);
	if (ret) {
		mbedtls_md_free(&ctx);
		jwt_freemem(*out);
		return 1;
	}

	/* Start HMAC calculation */
	ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
	if (!ret)
		ret = mbedtls_md_hmac_update(&ctx, (const unsigned char *)str,
				       str_len);
	if (!ret)
		ret = mbedtls_md_hmac_finish(&ctx, (unsigned char *)*out);
	if (ret) {
		mbedtls_md_free(&ctx);
		jwt_freemem(*out);
		return 1;
	}

	/* Get the output size */
	*len = mbedtls_md_get_size(md_info);

	mbedtls_md_free(&ctx);

	return 0;
}

static int mbedtls_verify_sha_hmac(jwt_t *jwt, const char *head,
				   unsigned int head_len, const char *sig)
{
	char *res;
	unsigned int res_len;
	char *buf = NULL;
	int ret;

	ret = mbedtls_sign_sha_hmac(jwt, &res, &res_len, head, head_len);
	if (ret)
		return ret; // LCOV_EXCL_LINE

	ret = jwt_base64uri_encode(&buf, (char *)res, res_len);
	if (ret <= 0) {
		// LCOV_EXCL_START
		jwt_freemem(res);
		return -ret;
		// LCOV_EXCL_STOP
	}

	ret = jwt_strcmp(buf, sig) ? 1 : 0;
	jwt_freemem(buf);
	jwt_freemem(res);

	/* And now... */
	return ret;
}

static int mbedtls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	size_t out_size;
	mbedtls_pk_context pk;
	const mbedtls_md_info_t *md_info;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	size_t sig_len = 0;
	int ret = 1;
	const char *pers = "libjwt_ecdsa_sign";

	if (jwt->key->pem == NULL) {
		jwt_write_error(jwt, "Not a compatible request for mbedTLS");
		return 1;
	}

	mbedtls_pk_init(&pk);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
			&entropy, (const unsigned char *)pers, strlen(pers))) {
		jwt_write_error(jwt, "Failed RNG setup for mbedTLS");
		goto sign_clean_key;
	}

	/* Load the private key */
	if (mbedtls_pk_parse_key(&pk, (unsigned char *)jwt->key->pem,
				 strlen(jwt->key->pem) + 1,
				 NULL, 0, NULL, NULL)) {
		jwt_write_error(jwt, "Error parsing private key");
		goto sign_clean_key;
	}

	/* Determine the hash algorithm */
	switch (jwt->alg) {
	case JWT_ALG_RS256:
	case JWT_ALG_PS256:
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;
	case JWT_ALG_RS384:
	case JWT_ALG_PS384:
	case JWT_ALG_ES384:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		break;
	case JWT_ALG_RS512:
	case JWT_ALG_PS512:
	case JWT_ALG_ES512:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		break;
	default:
		jwt_write_error(jwt, "Unsupported algorithm");
		goto sign_clean_key;
	}

	if (md_info == NULL) {
		jwt_write_error(jwt, "Failed to get hash algorithm info");
		goto sign_clean_key;
	}

	/* Compute the hash of the input string */
	if (mbedtls_md(md_info, (unsigned char *)str, str_len, hash)) {
		jwt_write_error(jwt, "Error initializing md context");
		goto sign_clean_key;
	}

	/* For EC keys, convert signature to R/S format */
	if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
		mbedtls_mpi r, s;
		mbedtls_ecdsa_context ecdsa;
		int adj;

		mbedtls_ecdsa_init(&ecdsa);
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		/* Extract ECDSA key */
		ret = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(pk));
		if (ret) {
			jwt_write_error(jwt,
				"Failed to extract ECDSA key");
			goto sign_clean_key;
		}

		if (mbedtls_ecdsa_sign(&ecdsa.private_grp, &r, &s,
				       &ecdsa.private_d, hash,
				       mbedtls_md_get_size(md_info),
				       mbedtls_ctr_drbg_random, &ctr_drbg)) {
			jwt_write_error(jwt, "Error signing token");
			goto sign_clean_key;
		}

		/* Determine R/S sizes based on algorithm */
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
		default:
			jwt_write_error(jwt,
				"Invalid EC alg");
			goto sign_clean_key;
		}

		out_size = adj * 2;
		*out = jwt_malloc(out_size);
		if (*out == NULL) {
			jwt_write_error(jwt,
				"Failed to allocate output buffer");
			goto sign_clean_key;
		}
		memset(*out, 0, out_size);

		mbedtls_mpi_write_binary(&r, (unsigned char *)(*out), adj);
		mbedtls_mpi_write_binary(&s, (unsigned char *)(*out) + adj, adj);

		*len = out_size;

		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);
		mbedtls_ecdsa_free(&ecdsa);
	} else {
		/* For RSA, use the sig directly */
		if (mbedtls_rsa_pkcs1_sign(mbedtls_pk_rsa(pk),
					   mbedtls_ctr_drbg_random,
					   &ctr_drbg,
					   mbedtls_md_get_type(md_info),
					   mbedtls_md_get_size(md_info),
					   hash, sig)) {
			jwt_write_error(jwt, "Error signing token");
			goto sign_clean_key;
		}

		sig_len = mbedtls_pk_rsa(pk)->private_len;

		*out = jwt_malloc(sig_len);
		if (*out == NULL) {
			jwt_write_error(jwt,
				"Failed to allocate output buffer");
			goto sign_clean_key;
		}
		memcpy(*out, sig, sig_len);
		*len = sig_len;
	}

	ret = 0; /* Success */

sign_clean_key:
	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return ret;
}

static int mbedtls_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len, const char *sig_b64)
{
	mbedtls_pk_context pk;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info = NULL;
	unsigned char *sig = NULL;
	size_t sig_len = 0;
	int ret = 1;

	mbedtls_pk_init(&pk);

	if (jwt->key->pem == NULL)
		return 1;

	/* Attempt to parse the key as a public key */
	ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)
					  jwt->key->pem,
					  strlen(jwt->key->pem) + 1);
	if (ret) {
		ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)
					   jwt->key->pem,
					   strlen(jwt->key->pem) + 1,
					   NULL, 0, NULL, NULL);
		if (ret) {
			jwt_write_error(jwt, "Failed to parse key");
			goto verify_clean_key;
		}
	}

	/* Determine the hash algorithm */
	switch (jwt->alg) {
	case JWT_ALG_RS256:
	case JWT_ALG_PS256:
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;
	case JWT_ALG_RS384:
	case JWT_ALG_PS384:
	case JWT_ALG_ES384:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		break;
	case JWT_ALG_RS512:
	case JWT_ALG_PS512:
	case JWT_ALG_ES512:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		break;
	default:
		jwt_write_error(jwt, "Unsupported algorithm");
		goto verify_clean_key;
	}

	if (md_info == NULL) {
		jwt_write_error(jwt, "Failed to get hash algorithm info");
		goto verify_clean_key;
	}

	/* Compute the hash of the input string */
	if ((ret = mbedtls_md(md_info, (const unsigned char *)head, head_len,
			      hash))) {
		jwt_write_error(jwt, "Failed to compute hash: %d", ret);
		goto verify_clean_key;
	}

	/* Decode the base64url signature */
	sig = jwt_base64uri_decode(sig_b64, (int *)&sig_len);
	if (sig == NULL) {
		jwt_write_error(jwt, "Failed to decode signature");
		goto verify_clean_key;
	}

	/* Handle ECDSA R/S format conversion */
	if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
		mbedtls_mpi r, s;
		mbedtls_ecdsa_context ecdsa;
		mbedtls_ecdsa_init(&ecdsa);
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		/* Split R/S from the signature */
		if (sig_len == 64 || sig_len == 96 || sig_len == 132) {
			size_t r_size = sig_len / 2;
			mbedtls_mpi_read_binary(&r, sig, r_size);
			mbedtls_mpi_read_binary(&s, sig + r_size, r_size);
		} else {
			jwt_write_error(jwt, "Invalid ECDSA signature size");
			goto verify_clean_sig;
		}

		/* Extract ECDSA public key */
		ret = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(pk));
		if (ret) {
			jwt_write_error(jwt,
				"Failed to extract ECDSA public key");
			goto verify_clean_sig;
		}

		/* Verify ECDSA signature */
		ret = mbedtls_ecdsa_verify(&ecdsa.private_grp, hash,
			mbedtls_md_get_size(md_info), &ecdsa.private_Q, &r, &s);
		if (ret) {
			jwt_write_error(jwt,
				"ECDSA signature verification failed");
			goto verify_clean_sig;
		}

		/* Free ECDSA resources */
		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);
		mbedtls_ecdsa_free(&ecdsa);
	} else if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
		/* Verify RSA or RSA-PSS signature */
		if (jwt->alg == JWT_ALG_PS256 || jwt->alg == JWT_ALG_PS384 ||
		    jwt->alg == JWT_ALG_PS512) {
			ret = mbedtls_rsa_rsassa_pss_verify(mbedtls_pk_rsa(pk),
					mbedtls_md_get_type(md_info),
					mbedtls_md_get_size(md_info),
					hash, sig);
		} else {
			ret = mbedtls_pk_verify(&pk,
					mbedtls_md_get_type(md_info), hash,
				mbedtls_md_get_size(md_info), sig, sig_len);
		}

		if (ret) {
			jwt_write_error(jwt,
				"RSA signature verification failed");
			goto verify_clean_sig;
		}
	} else {
		jwt_write_error(jwt, "Unsupported key type for verification");
		goto verify_clean_sig;
	}

verify_clean_sig:
	jwt_freemem(sig);

verify_clean_key:
	mbedtls_pk_free(&pk);

	return jwt->error;
}

/* Export our ops */
struct jwt_crypto_ops jwt_mbedtls_ops = {
	.name			= "mbedtls",
	.provider		= JWT_CRYPTO_OPS_MBEDTLS,

	.sign_sha_hmac		= mbedtls_sign_sha_hmac,
	.verify_sha_hmac	= mbedtls_verify_sha_hmac,
	.sign_sha_pem		= mbedtls_sign_sha_pem,
	.verify_sha_pem		= mbedtls_verify_sha_pem,

	/* Needs to be implemented */
	.jwk_implemented	= 1,
	.process_eddsa		= openssl_process_eddsa,
	.process_rsa		= openssl_process_rsa,
	.process_ec		= openssl_process_ec,
	.process_item_free	= openssl_process_item_free,
};
