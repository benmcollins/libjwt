/* Copyright (C) 2015-2024 Ben Collins <bcollins@maclara-llc.com>
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

/* Routines to support crypto in LibJWT using OpenSSL. */

static int openssl_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
				 const char *str, unsigned int str_len)
{
	const EVP_MD *alg;

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

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)str, str_len, (unsigned char *)*out,
	     len);

	return 0;
}

static int openssl_verify_sha_hmac(jwt_t *jwt, const char *head,
				   unsigned int head_len, const char *sig)
{
	unsigned char res[EVP_MAX_MD_SIZE];
	unsigned int res_len;
	const EVP_MD *alg;
	char *buf = NULL;
	int ret;

	switch (jwt->alg) {
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

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)head, head_len, res, &res_len);

	ret = jwt_base64uri_encode(&buf, (char *)res, res_len);
	if (ret <= 0)
		return -ret;

	ret = jwt_strcmp(buf, sig) ? EINVAL : 0;
	jwt_freemem(buf);

	/* And now... */
	return ret;
}

#define EC_ERROR(__err) { return -(__err); }

static int __degree_and_check(EVP_PKEY *pkey, jwt_t *jwt)
{
	int degree, curve_nid;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	const EC_GROUP *group;
	const EC_KEY *ec_key;

	ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	if (ec_key == NULL)
		EC_ERROR(EINVAL);

	group = EC_KEY_get0_group(ec_key);
	if (group == NULL)
		EC_ERROR(EINVAL);

	curve_nid = EC_GROUP_get_curve_name(group);
	degree = EC_GROUP_get_degree(group);
#else
	EC_GROUP *group;
	char curve_name[80];
	size_t len;

	if (!EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name), &len))
		EC_ERROR(EINVAL);
	curve_name[len] = '\0';

	curve_nid = OBJ_txt2nid(curve_name);
	if (curve_nid == NID_undef)
		EC_ERROR(EINVAL);
	group = EC_GROUP_new_by_curve_name(curve_nid);
	if (group == NULL)
		EC_ERROR(EINVAL);

	degree = EC_GROUP_get_degree(group);
	EC_GROUP_free(group);
#endif

	/* We only perform this check for ES256K. All others we just check
	 * the degree (bits). */
	if (jwt->alg == JWT_ALG_ES256K && curve_nid != NID_secp256k1)
		EC_ERROR(EINVAL);

	return degree;
}

static int jwt_degree_for_key(EVP_PKEY *pkey, jwt_t *jwt)
{
	int degree = __degree_and_check(pkey, jwt);

	if (degree < 0)
		return degree;

	/* Final check for matching degree */
	switch (jwt->alg) {
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		if (degree != 256)
			EC_ERROR(EINVAL);
		break;
	case JWT_ALG_ES384:
		if (degree != 384)
			EC_ERROR(EINVAL);
		break;
	case JWT_ALG_ES512:
		/* This is not a typo. ES512 uses secp521r1 */
		if (degree != 521)
			EC_ERROR(EINVAL);
		break;
	default:
		EC_ERROR(EINVAL);
	}

	return degree;
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

	degree = jwt_degree_for_key(pkey, jwt);
	if (degree < 0)
		return -degree;

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
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	BIO *bufkey = NULL;
	const EVP_MD *alg;
	int type;
	EVP_PKEY *pkey = NULL;
	unsigned char *sig = NULL;
	int ret = 0;
	size_t slen;

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
		type = EVP_PKEY_ED25519;
		break;

	default:
		return EINVAL;
	}

	bufkey = BIO_new_mem_buf(jwt->key, jwt->key_len);
	if (bufkey == NULL)
		SIGN_ERROR(ENOMEM); // LCOV_EXCL_LINE

	/* This uses OpenSSL's default passphrase callback if needed. The
	 * library caller can override this in many ways, all of which are
	 * outside of the scope of LibJWT and this is documented in jwt.h. */
	pkey = PEM_read_bio_PrivateKey(bufkey, NULL, NULL, NULL);
	if (pkey == NULL)
		SIGN_ERROR(EINVAL);

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
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(mdctx);

	return ret;
}

#define VERIFY_ERROR(__err) { ret = __err; goto jwt_verify_sha_pem_done; }

static int openssl_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len, const char *sig_b64)
{
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
		type = EVP_PKEY_ED25519;
		break;

	default:
		return EINVAL;
	}

	sig = jwt_base64uri_decode(sig_b64, &slen);
	if (sig == NULL)
		VERIFY_ERROR(EINVAL);

	bufkey = BIO_new_mem_buf(jwt->key, jwt->key_len);
	if (bufkey == NULL)
		VERIFY_ERROR(ENOMEM); // LCOV_EXCL_LINE

	/* This uses OpenSSL's default passphrase callback if needed. The
	 * library caller can override this in many ways, all of which are
	 * outside of the scope of LibJWT and this is documented in jwt.h. */
	pkey = PEM_read_bio_PUBKEY(bufkey, NULL, NULL, NULL);
	if (pkey == NULL)
		VERIFY_ERROR(EINVAL);

	if (type != EVP_PKEY_id(pkey))
		VERIFY_ERROR(EINVAL);

	/* Convert EC sigs back to ASN1. */
	if (type == EVP_PKEY_EC) {
		unsigned int bn_len;
		int degree;
		unsigned char *p;

		ec_sig = ECDSA_SIG_new();
		if (ec_sig == NULL)
			VERIFY_ERROR(ENOMEM); // LCOV_EXCL_LINE

		degree = jwt_degree_for_key(pkey, jwt);
		if (degree < 0)
			VERIFY_ERROR(-degree);

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
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(mdctx);
	jwt_freemem(sig);
	ECDSA_SIG_free(ec_sig);

	return ret;
}

int openssl_process_eddsa(json_t *jwk, jwk_item_t *item);
int openssl_process_rsa(json_t *jwk, jwk_item_t *item);
int openssl_process_ec(json_t *jwk, jwk_item_t *item);
void openssl_process_item_free(jwk_item_t *item);

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
