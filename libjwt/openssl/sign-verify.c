/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include <jwt.h>

#include "jwt-private.h"

#include "openssl/jwt-openssl.h"

/* Routines to support crypto in LibJWT using OpenSSL. */

static int openssl_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
				 const char *str, unsigned int str_len)
{
	const EVP_MD *alg;
	void *key;
	size_t key_len;

	key = jwt->key->oct.key;
	key_len = jwt->key->oct.len;

	*out = NULL;

	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
		alg = EVP_sha256();
		break;
	case JWT_ALG_HS384:
		alg = EVP_sha384();
		break;
	case JWT_ALG_HS512:
		alg = EVP_sha512();
		break;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	*out = jwt_malloc(EVP_MAX_MD_SIZE);
	if (*out == NULL)
		return 1; // LCOV_EXCL_LINE

	if (HMAC(alg, key, key_len, (const unsigned char *)str, str_len,
		 (unsigned char *)*out, len) == NULL) {
		// LCOV_EXCL_START
		jwt_freemem(*out);
		*out = NULL;
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

static int jwt_ec_d2i(jwt_t *jwt, char **out, unsigned int *len,
		      unsigned char *sig, unsigned int slen)
{
	unsigned int bn_len, r_len, s_len, buf_len;
	ECDSA_SIG *ec_sig = NULL;
	const BIGNUM *ec_sig_r;
	const BIGNUM *ec_sig_s;
	unsigned char *buf;

	/* Get the sig from the DER encoded version. */
	ec_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig, slen);
	if (ec_sig == NULL)
		return 1; // LCOV_EXCL_LINE

	ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
	r_len = BN_num_bytes(ec_sig_r);
	s_len = BN_num_bytes(ec_sig_s);
	bn_len = (jwt->key->bits + 7) / 8;
	if ((r_len > bn_len) || (s_len > bn_len)) {
		// LCOV_EXCL_START
		ECDSA_SIG_free(ec_sig);
		return 1;
		// LCOV_EXCL_STOP
	}

	buf_len = 2 * bn_len;
	buf = jwt_malloc(buf_len);
	if (buf == NULL) {
		// LCOV_EXCL_START
		ECDSA_SIG_free(ec_sig);
		return 1;
		// LCOV_EXCL_STOP
	}

	/* Pad the bignums with leading zeroes. Ends up looking sort
	 * of like this "0000rrrrrrrSSSSS". */
	memset(buf, 0, buf_len);
	BN_bn2bin(ec_sig_r, buf + (bn_len - r_len));
	BN_bn2bin(ec_sig_s, buf + (buf_len - s_len));

	ECDSA_SIG_free(ec_sig);

	*out = (char *)buf;
	*len = buf_len;

	return 0;
}

#define SIGN_ERROR(_msg) { jwt_write_error(jwt, "JWT[OpenSSL]: " _msg); goto jwt_sign_sha_pem_done; }

static int openssl_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	BIO *bufkey = NULL;
	const EVP_MD *alg;
	int type;
	EVP_PKEY *pkey = NULL;
	unsigned char *sig = NULL;
	size_t slen;

	pkey = jwt->key->provider_data;

	switch (jwt->alg) {
	/* RSA */
	case JWT_ALG_RS256:
		alg = EVP_sha256();
		type = EVP_PKEY_RSA;
		break;
	case JWT_ALG_RS384:
		alg = EVP_sha384();
		type = EVP_PKEY_RSA;
		break;
	case JWT_ALG_RS512:
		alg = EVP_sha512();
		type = EVP_PKEY_RSA;
		break;

	/* RSA-PSS */
	case JWT_ALG_PS256:
		alg = EVP_sha256();
		type = EVP_PKEY_RSA_PSS;
		break;
	case JWT_ALG_PS384:
		alg = EVP_sha384();
		type = EVP_PKEY_RSA_PSS;
		break;
	case JWT_ALG_PS512:
		alg = EVP_sha512();
		type = EVP_PKEY_RSA_PSS;
		break;

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		alg = EVP_sha256();
		type = EVP_PKEY_EC;
		break;
	case JWT_ALG_ES384:
		alg = EVP_sha384();
		type = EVP_PKEY_EC;
		break;
	case JWT_ALG_ES512:
		alg = EVP_sha512();
		type = EVP_PKEY_EC;
		break;

	/* EdDSA */
	case JWT_ALG_EDDSA:
		/* Technically this is sha512 for ED25519 and
		 * shake256 for ED448 */
		alg = EVP_md_null();
		type = EVP_PKEY_id(pkey);
		if (type != EVP_PKEY_ED25519 && type != EVP_PKEY_ED448)
			SIGN_ERROR("Unknown EdDSA curve"); // LCOV_EXCL_LINE
		break;

	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	if (type == EVP_PKEY_RSA_PSS) {
	       if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA &&
		   EVP_PKEY_id(pkey) != EVP_PKEY_RSA_PSS) {
			SIGN_ERROR("Incompatible key for RSASSA-PSS"); // LCOV_EXCL_LINE
	       }
	} else if (type != EVP_PKEY_id(pkey)) {
		SIGN_ERROR("Incompatible key"); // LCOV_EXCL_LINE
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		SIGN_ERROR("Error creating MD context"); // LCOV_EXCL_LINE

	/* Initialize the DigestSign operation using alg */
	if (EVP_DigestSignInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
		SIGN_ERROR("Failued to initialize digest"); // LCOV_EXCL_LINE

	/* Required for RSA-PSS */
	if (type == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
						RSA_PKCS1_PSS_PADDING) < 0)
			SIGN_ERROR("Error setting RSASSA-PSS padding"); // LCOV_EXCL_LINE
		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx,
						RSA_PSS_SALTLEN_DIGEST) < 0)
			SIGN_ERROR("Error setting RSASSA-PSS salt length"); // LCOV_EXCL_LINE
	}

	/* Get the size of sig first */
	if (EVP_DigestSign(mdctx, NULL, &slen, (const unsigned char *)str,
			   str_len) != 1)
		SIGN_ERROR("Error checking sig size"); // LCOV_EXCL_LINE

	/* Allocate memory for signature based on returned size */
	sig = jwt_malloc(slen);
	if (sig == NULL)
		SIGN_ERROR("Out of memory"); // LCOV_EXCL_LINE

	/* Actual signing */
	if (EVP_DigestSign(mdctx, sig, &slen, (const unsigned char *)str,
			   str_len) != 1)
		SIGN_ERROR("Error singing token") // LCOV_EXCL_LINE;

	if (type == EVP_PKEY_EC) {
		/* For EC we need to convert to a raw format of R/S. */
		if (jwt_ec_d2i(jwt, out, len, sig, slen))
			SIGN_ERROR("ECDSA failed d2i"); // LCOV_EXCL_LINE

		/* jwt_ec_d2i has updated the out and len pointers on
		 * success. Either way, we're done with this buffer. */
		jwt_freemem(sig);
		sig = NULL;
	} else {
		/* Everything else, just pass back the original sig. */
		*out = (char *)sig;
		*len = slen;
	}

jwt_sign_sha_pem_done:
	if (jwt->error)
		jwt_freemem(sig); // LCOV_EXCL_LINE

	BIO_free(bufkey);
	EVP_MD_CTX_destroy(mdctx);

	return jwt->error;
}

#define VERIFY_ERROR(_msg) { jwt_write_error(jwt, "JWT[OpenSSL]: " _msg); goto jwt_verify_sha_pem_done; }

static int openssl_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len,
				  unsigned char *sig, int slen)
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *ec_sig_r = NULL;
	BIGNUM *ec_sig_s = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *alg;
	int type;
	BIO *bufkey = NULL;

	pkey = jwt->key->provider_data;

	switch (jwt->alg) {
	/* RSA */
	case JWT_ALG_RS256:
		alg = EVP_sha256();
		type = EVP_PKEY_RSA;
		break;
	case JWT_ALG_RS384:
		alg = EVP_sha384();
		type = EVP_PKEY_RSA;
		break;
	case JWT_ALG_RS512:
		alg = EVP_sha512();
		type = EVP_PKEY_RSA;
		break;

	/* RSA-PSS */
	case JWT_ALG_PS256:
		alg = EVP_sha256();
		type = EVP_PKEY_RSA_PSS;
		break;
	case JWT_ALG_PS384:
		alg = EVP_sha384();
		type = EVP_PKEY_RSA_PSS;
		break;
	case JWT_ALG_PS512:
		alg = EVP_sha512();
		type = EVP_PKEY_RSA_PSS;
		break;

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		alg = EVP_sha256();
		type = EVP_PKEY_EC;
		break;
	case JWT_ALG_ES384:
		alg = EVP_sha384();
		type = EVP_PKEY_EC;
		break;
	case JWT_ALG_ES512:
		alg = EVP_sha512();
		type = EVP_PKEY_EC;
		break;

	/* EdDSA */
	case JWT_ALG_EDDSA:
		alg = NULL;
		if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 ||
		    EVP_PKEY_id(pkey) == EVP_PKEY_ED448)
			type = EVP_PKEY_id(pkey);
		else
			VERIFY_ERROR("Unknown EdDSA curve"); // LCOV_EXCL_LINE
		break;

	// LCOV_EXCL_START
	default:
		VERIFY_ERROR("Unknown algorithm");
	// LCOV_EXCL_STOP
	}

	if (type == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA_PSS &&
		    EVP_PKEY_id(pkey) != EVP_PKEY_RSA)
			VERIFY_ERROR("Incompatible key for RSASSA-PSS"); // LCOV_EXCL_LINE
	} else if (type != EVP_PKEY_id(pkey))
		VERIFY_ERROR("Incompatible key for algorithm");

        if (type == EVP_PKEY_EC) {
		/* Convert EC sigs back to ASN1. */
		unsigned int bn_len;
		unsigned char *p;

		ec_sig = ECDSA_SIG_new();
		if (ec_sig == NULL)
			VERIFY_ERROR("Failed to allocate ECDSA sig"); // LCOV_EXCL_LINE

		bn_len = (jwt->key->bits + 7) / 8;
		if ((bn_len * 2) != (unsigned int)slen)
			VERIFY_ERROR("ECDSA micmatch with sig len"); // LCOV_EXCL_LINE

		ec_sig_r = BN_bin2bn(sig, bn_len, NULL);
		ec_sig_s = BN_bin2bn(sig + bn_len, bn_len, NULL);
		if (ec_sig_r  == NULL || ec_sig_s == NULL)
			VERIFY_ERROR("Error allocating R/S params"); // LCOV_EXCL_LINE

		ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s);

		slen = i2d_ECDSA_SIG(ec_sig, NULL);

		/* Reset this with the new information */
		sig = jwt_malloc(slen);
		if (sig == NULL)
			VERIFY_ERROR("Out of memory"); // LCOV_EXCL_LINE

		p = sig;
		slen = i2d_ECDSA_SIG(ec_sig, &p);

		if (slen == 0)
			VERIFY_ERROR("Error calculating ECDSA sig"); // LCOV_EXCL_LINE
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		VERIFY_ERROR("Error creatign MD context"); // LCOV_EXCL_LINE

	/* Initialize the DigestVerify operation using alg */
	if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
		VERIFY_ERROR("Error initializing mdctx"); // LCOV_EXCL_LINE

	if (type == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
						 RSA_PKCS1_PSS_PADDING) < 0)
			VERIFY_ERROR("Error setting RSASSA-PSS padding"); // LCOV_EXCL_LINE
		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx,
						     RSA_PSS_SALTLEN_AUTO) < 0)
			VERIFY_ERROR("Error setting RSASSA-PSS salt length"); // LCOV_EXCL_LINE
	}

	/* One-shot update and verify */
	if (EVP_DigestVerify(mdctx, sig, slen, (const unsigned char *)head,
			     head_len) != 1)
		VERIFY_ERROR("Failed to verify signature");

jwt_verify_sha_pem_done:
	BIO_free(bufkey);
	EVP_MD_CTX_destroy(mdctx);
	ECDSA_SIG_free(ec_sig);

	return jwt->error;
}

/* Export our ops */
struct jwt_crypto_ops jwt_openssl_ops = {
	.name			= "openssl",
	.provider		= JWT_CRYPTO_OPS_OPENSSL,

	.sign_sha_hmac		= openssl_sign_sha_hmac,
	.sign_sha_pem		= openssl_sign_sha_pem,
	.verify_sha_pem		= openssl_verify_sha_pem,

	.jwk_implemented	= 1,
	.process_eddsa		= openssl_process_eddsa,
	.process_rsa		= openssl_process_rsa,
	.process_ec		= openssl_process_ec,
	.process_item_free	= openssl_process_item_free,
};
