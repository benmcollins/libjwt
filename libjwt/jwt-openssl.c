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

/* Functions to make libjwt backward compatible with OpenSSL version < 1.1.0
 * See https://wiki.openssl.org/index.php/1.1_API_Changes
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
	if (pr != NULL)
		*pr = sig->r;
	if (ps != NULL)
		*ps = sig->s;
}

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return 1;
}

#endif

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
		return ENOMEM;

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
	char *buf;

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

	buf = alloca(head_len + 1);
	if (!buf) {
		return ENOMEM;
	}

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)head, head_len, res, &res_len);

	jwt_base64uri_encode(buf, (char *)res, res_len);

	/* And now... */
	return jwt_strcmp(buf, sig) ? EINVAL : 0;
}

#define EC_ERROR(__err) { return -(__err); }

static size_t __degree_and_check(EVP_PKEY *pkey, jwt_t *jwt)
{
	size_t degree;
	int curve_nid;

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
	size_t degree = __degree_and_check(pkey, jwt);

	/* Final check for matching degree */
	switch (jwt->alg) {
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		if (degree != 256)
			return -EINVAL;
		break;
	case JWT_ALG_ES384:
		if (degree != 384)
			return -EINVAL;
		break;
	case JWT_ALG_ES512:
		/* This is not a typo. ES512 uses secp521r1 */
		if (degree != 521)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return degree;
}

#define SIGN_ERROR(__err) { ret = __err; goto jwt_sign_sha_pem_done; }

static int openssl_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	const BIGNUM *ec_sig_r = NULL;
	const BIGNUM *ec_sig_s = NULL;
	BIO *bufkey = NULL;
	const EVP_MD *alg;
	int type;
	EVP_PKEY *pkey = NULL;
	unsigned char *sig;
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
		SIGN_ERROR(ENOMEM);

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
		SIGN_ERROR(ENOMEM);

	/* Initialize the DigestSign operation using alg */
	if (EVP_DigestSignInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
		SIGN_ERROR(EINVAL);

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
	sig = alloca(slen);
	if (sig == NULL)
		SIGN_ERROR(ENOMEM);

	/* Actual signing */
	if (EVP_DigestSign(mdctx, sig, &slen, (const unsigned char *)str, str_len) != 1)
		SIGN_ERROR(EINVAL);

	if (type != EVP_PKEY_EC) {
		*out = jwt_malloc(slen);
		if (*out == NULL)
			SIGN_ERROR(ENOMEM);
		memcpy(*out, sig, slen);
		*len = slen;
	} else {
		unsigned int bn_len, r_len, s_len, buf_len;
		unsigned char *raw_buf;

		/* For EC we need to convert to a raw format of R/S. */
		int degree = jwt_degree_for_key(pkey, jwt);
		if (degree < 0)
			SIGN_ERROR(-degree);

		/* Get the sig from the DER encoded version. */
		ec_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig, slen);
		if (ec_sig == NULL)
			SIGN_ERROR(ENOMEM);

		ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
		r_len = BN_num_bytes(ec_sig_r);
		s_len = BN_num_bytes(ec_sig_s);
		bn_len = (degree + 7) / 8;
		if ((r_len > bn_len) || (s_len > bn_len))
			SIGN_ERROR(EINVAL);

		buf_len = 2 * bn_len;
		raw_buf = alloca(buf_len);
		if (raw_buf == NULL)
			SIGN_ERROR(ENOMEM);

		/* Pad the bignums with leading zeroes. */
		memset(raw_buf, 0, buf_len);
		BN_bn2bin(ec_sig_r, raw_buf + bn_len - r_len);
		BN_bn2bin(ec_sig_s, raw_buf + buf_len - s_len);

		*out = jwt_malloc(buf_len);
		if (*out == NULL)
			SIGN_ERROR(ENOMEM);
		memcpy(*out, raw_buf, buf_len);
		*len = buf_len;
	}

jwt_sign_sha_pem_done:
	if (bufkey)
		BIO_free(bufkey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (ec_sig)
		ECDSA_SIG_free(ec_sig);

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
		VERIFY_ERROR(ENOMEM);

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
			VERIFY_ERROR(ENOMEM);

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
		jwt_freemem(sig);

		slen = i2d_ECDSA_SIG(ec_sig, NULL);
		sig = jwt_malloc(slen);
		if (sig == NULL)
			VERIFY_ERROR(ENOMEM);

		p = sig;
		slen = i2d_ECDSA_SIG(ec_sig, &p);

		if (slen == 0)
			VERIFY_ERROR(EINVAL);
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		VERIFY_ERROR(ENOMEM);

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
	if (bufkey)
		BIO_free(bufkey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (sig)
		jwt_freemem(sig);
	if (ec_sig)
		ECDSA_SIG_free(ec_sig);

	return ret;
}

/* Export our ops */
struct jwt_crypto_ops jwt_openssl_ops = {
	.name			= "openssl",
	.sign_sha_hmac		= openssl_sign_sha_hmac,
	.verify_sha_hmac	= openssl_verify_sha_hmac,
	.sign_sha_pem		= openssl_sign_sha_pem,
	.verify_sha_pem		= openssl_verify_sha_pem,
};
