/* Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

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

	key = jwt->jw_key->oct.key;
	key_len = jwt->jw_key->oct.len;

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
	default:
		return EINVAL;
	}

	*out = jwt_malloc(EVP_MAX_MD_SIZE);
	if (*out == NULL)
		return ENOMEM; // LCOV_EXCL_LINE

	if (HMAC(alg, key, key_len, (const unsigned char *)str, str_len,
		 (unsigned char *)*out, len) == NULL) {
		jwt_freemem(*out);
		*out = NULL;
		return EINVAL;
	}

	return 0;
}

static int openssl_verify_sha_hmac(jwt_t *jwt, const char *head,
				   unsigned int head_len, const char *sig)
{
	char *res;
	unsigned int res_len;
	char *buf = NULL;
	int ret;

	ret = openssl_sign_sha_hmac(jwt, &res, &res_len, head, head_len);
	if (ret)
		return ret;

	ret = jwt_base64uri_encode(&buf, (char *)res, res_len);
	if (ret <= 0) {
		jwt_freemem(res);
		return -ret;
	}

	ret = jwt_strcmp(buf, sig) ? EINVAL : 0;
	jwt_freemem(buf);
	jwt_freemem(res);

	/* And now... */
	return ret;
}

static int __degree_and_check(EVP_PKEY *pkey, jwt_t *jwt)
{
	int bits = jwt->jw_key->bits;

	switch (jwt->alg) {
	case JWT_ALG_ES256:
		if (bits != 256 || strcmp(jwt->jw_key->curve, "P-256"))
			return 0;
		break;

	case JWT_ALG_ES384:
		if (bits != 384 || strcmp(jwt->jw_key->curve, "P-384"))
                        return 0;
		break;

	case JWT_ALG_ES512:
		if (bits != 521 || strcmp(jwt->jw_key->curve, "P-521"))
                        return 0;
		break;

	case JWT_ALG_ES256K:
		if (bits != 256 || strcmp(jwt->jw_key->curve, "secp256k1"))
                        return 0;
		break;

	default:
		return 0;
	}

	return bits;
}

static int jwt_ec_d2i(jwt_t *jwt, char **out, unsigned int *len,
		      unsigned char *sig, unsigned int slen,
		      EVP_PKEY *pkey)
{
	unsigned int bn_len, r_len, s_len, buf_len;
	ECDSA_SIG *ec_sig = NULL;
	const BIGNUM *ec_sig_r;
	const BIGNUM *ec_sig_s;
	unsigned char *buf;
	int degree;

	degree = __degree_and_check(pkey, jwt);
	if (degree <= 0)
		return EINVAL;

	/* Get the sig from the DER encoded version. */
	ec_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig, slen);
	if (ec_sig == NULL)
		return ENOMEM; // LCOV_EXCL_LINE

	ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
	r_len = BN_num_bytes(ec_sig_r);
	s_len = BN_num_bytes(ec_sig_s);
	bn_len = (degree + 7) / 8;
	if ((r_len > bn_len) || (s_len > bn_len)) {
		ECDSA_SIG_free(ec_sig);
		return EINVAL;
	}

	buf_len = 2 * bn_len;
	buf = jwt_malloc(buf_len);
	if (buf == NULL) {
		// LCOV_EXCL_START
		ECDSA_SIG_free(ec_sig);
		return ENOMEM;
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

#define SIGN_ERROR(__err) { ret = __err; goto jwt_sign_sha_pem_done; }

static int openssl_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	jwk_openssl_ctx_t *jwk_ctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	BIO *bufkey = NULL;
	const EVP_MD *alg;
	int type;
	EVP_PKEY *pkey = NULL;
	unsigned char *sig = NULL;
	int ret = 0;
	size_t slen;

	if (!ops_compat(jwt->jw_key, JWT_CRYPTO_OPS_OPENSSL))
		return EINVAL;

	jwk_ctx = jwt->jw_key->provider_data;
	pkey = jwk_ctx->pkey;

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
			type = -1;
		break;

	default:
		return EINVAL;
	}

	if (type != EVP_PKEY_id(pkey))
		SIGN_ERROR(EINVAL);

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		SIGN_ERROR(ENOMEM); // LCOV_EXCL_LINE

	/* Initialize the DigestSign operation using alg */
	if (EVP_DigestSignInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
		SIGN_ERROR(EINVAL);

	/* Required for RSA-PSS */
	if (type == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) < 0)
			SIGN_ERROR(EINVAL);
		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) < 0)
			SIGN_ERROR(EINVAL);
	}

	/* Get the size of sig first */
	if (EVP_DigestSign(mdctx, NULL, &slen, (const unsigned char *)str, str_len) != 1)
		SIGN_ERROR(EINVAL);

	/* Allocate memory for signature based on returned size */
	sig = jwt_malloc(slen);
	if (sig == NULL)
		SIGN_ERROR(ENOMEM); // LCOV_EXCL_LINE

	/* Actual signing */
	if (EVP_DigestSign(mdctx, sig, &slen, (const unsigned char *)str, str_len) != 1)
		SIGN_ERROR(EINVAL);

	if (type == EVP_PKEY_EC) {
		/* For EC we need to convert to a raw format of R/S. */
		ret = jwt_ec_d2i(jwt, out, len, sig, slen, pkey);

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
	if (ret)
		jwt_freemem(sig);

	BIO_free(bufkey);
	if (jwk_ctx == NULL)
		EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(mdctx);

	return ret;
}

#define VERIFY_ERROR(__err) { ret = __err; goto jwt_verify_sha_pem_done; }

static int openssl_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len, const char *sig_b64)
{
	jwk_openssl_ctx_t *jwk_ctx = NULL;
	unsigned char *sig = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *ec_sig_r = NULL;
	BIGNUM *ec_sig_s = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *alg;
	int type;
	BIO *bufkey = NULL;
	int ret = 0;
	int slen;

	if (!ops_compat(jwt->jw_key, JWT_CRYPTO_OPS_OPENSSL))
		return EINVAL;
	jwk_ctx = jwt->jw_key->provider_data;
	pkey = jwk_ctx->pkey;

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
			type = -1;
		break;

	default:
		return EINVAL;
	}

	sig = jwt_base64uri_decode(sig_b64, &slen);
	if (sig == NULL)
		VERIFY_ERROR(EINVAL);

	if (type != EVP_PKEY_id(pkey))
		VERIFY_ERROR(EINVAL);

	/* Convert EC sigs back to ASN1. */
	if (type == EVP_PKEY_EC) {
		unsigned int bn_len;
		int degree;
		unsigned char *p;

		degree = __degree_and_check(pkey, jwt);
		if (degree <= 0)
			VERIFY_ERROR(-degree);

		ec_sig = ECDSA_SIG_new();
		if (ec_sig == NULL)
			VERIFY_ERROR(ENOMEM); // LCOV_EXCL_LINE

		bn_len = (degree + 7) / 8;
		if ((bn_len * 2) != slen)
			VERIFY_ERROR(EINVAL);

		ec_sig_r = BN_bin2bn(sig, bn_len, NULL);
		ec_sig_s = BN_bin2bn(sig + bn_len, bn_len, NULL);
		if (ec_sig_r  == NULL || ec_sig_s == NULL)
			VERIFY_ERROR(EINVAL);

		ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s);

		slen = i2d_ECDSA_SIG(ec_sig, NULL);

		/* Reset this with the new information. */
		sig = jwt_realloc(sig, slen);
		if (sig == NULL)
			VERIFY_ERROR(ENOMEM); // LCOV_EXCL_LINE

		p = sig;
		slen = i2d_ECDSA_SIG(ec_sig, &p);

		if (slen == 0)
			VERIFY_ERROR(EINVAL);
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		VERIFY_ERROR(ENOMEM); // LCOV_EXCL_LINE

	/* Initialize the DigestVerify operation using alg */
	if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
		VERIFY_ERROR(EINVAL);

	if (type == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) < 0)
			VERIFY_ERROR(EINVAL);
		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) < 0)
			VERIFY_ERROR(EINVAL);
	}

	/* One-shot update and verify */
	if (EVP_DigestVerify(mdctx, sig, slen, (const unsigned char *)head, head_len) != 1)
		VERIFY_ERROR(EINVAL);

jwt_verify_sha_pem_done:
	BIO_free(bufkey);
	if (jwk_ctx == NULL)
		EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(mdctx);
	jwt_freemem(sig);
	ECDSA_SIG_free(ec_sig);

	return ret;
}

/* Export our ops */
struct jwt_crypto_ops jwt_openssl_ops = {
	.name			= "openssl",
	.provider		= JWT_CRYPTO_OPS_OPENSSL,

	.sign_sha_hmac		= openssl_sign_sha_hmac,
	.verify_sha_hmac	= openssl_verify_sha_hmac,
	.sign_sha_pem		= openssl_sign_sha_pem,
	.verify_sha_pem		= openssl_verify_sha_pem,

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	.jwk_implemented	= 1,
#else
	.jwk_implemented	= 0,
#endif
	.process_eddsa		= openssl_process_eddsa,
	.process_rsa		= openssl_process_rsa,
	.process_ec		= openssl_process_ec,
	.process_item_free	= openssl_process_item_free,
};
