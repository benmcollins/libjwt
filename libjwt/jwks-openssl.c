/* Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include <jwt.h>
#include "jwt-private.h"

#ifndef EVP_PKEY_PRIVATE_KEY
#define EVP_PKEY_PRIVATE_KEY EVP_PKEY_KEYPAIR
#endif

/* Sets a param for the public EC key */
static void *set_ec_pub_key(OSSL_PARAM_BLD *build, json_t *jx, json_t *jy,
			   const char *curve_name)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	unsigned char *bin_x = NULL, *bin_y = NULL;
	int len_x, len_y;
	const char *str_x, *str_y;
	BIGNUM *x = NULL, *y = NULL;
	int nid;
	size_t pub_key_len = 0;
	unsigned char *pub_key = NULL;

	/* First, base64url decode */
	str_x = json_string_value(jx);
	str_y = json_string_value(jy);
	if (str_x == NULL || str_y == NULL)
		goto ec_pub_key_cleanup;

	bin_x = jwt_base64uri_decode(str_x, &len_x);
	bin_y = jwt_base64uri_decode(str_y, &len_y);
	if (bin_x == NULL || bin_y == NULL)
		goto ec_pub_key_cleanup;

	/* Convert to BN */
	x = BN_bin2bn(bin_x, len_x, NULL);
	y = BN_bin2bn(bin_y, len_y, NULL);

	if (x == NULL || y == NULL)
		goto ec_pub_key_cleanup;

	/* Create the EC group and point */
	nid = OBJ_sn2nid(curve_name);
	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL)
		goto ec_pub_key_cleanup;

	point = EC_POINT_new(group);
	if (point == NULL)
		goto ec_pub_key_cleanup;

	if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
		goto ec_pub_key_cleanup;

	pub_key_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED,
					 &pub_key, NULL);
	if (pub_key_len == 0)
		goto ec_pub_key_cleanup;

	OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY, pub_key,
					 pub_key_len);

ec_pub_key_cleanup:
	EC_POINT_free(point);
	EC_GROUP_free(group);
	BN_free(x);
	BN_free(y);
	jwt_freemem(bin_x);
	jwt_freemem(bin_y);

	/* Return this to be freed. */
	return pub_key;
}

/* b64url-decodes a single OSSL BIGNUM and sets the OSSL param. */
static BIGNUM *set_one_bn(OSSL_PARAM_BLD *build, const char *ossl_name,
		       json_t *val)
{
	unsigned char *bin;
	const char *str;
	int len = 0;
	BIGNUM *bn;

	/* decode it */
	str = json_string_value(val);
	if (str == NULL)
		return NULL;
	bin = jwt_base64uri_decode(str, &len);

	if (bin == NULL || len <= 0)
		return NULL;

	bn = BN_bin2bn(bin, len, NULL);
	jwt_freemem(bin);

	if (bn == NULL)
		return NULL;

	OSSL_PARAM_BLD_push_BN(build, ossl_name, bn);

	return bn;
}

/* Sets a single OSSL string param. */
static void set_one_string(OSSL_PARAM_BLD *build, const char *ossl_name,
			   json_t *val)
{
	const char *str = json_string_value(val);
	int len = json_string_length(val);

	OSSL_PARAM_BLD_push_utf8_string(build, ossl_name, str, len);
}

/* b64url-decodes a single octet and creates an OSSL param. */
static unsigned char *set_one_octet(OSSL_PARAM_BLD *build,
				    const char *ossl_name, json_t *val)
{
	unsigned char *bin;
	const char *str;
	int len;

	/* decode it */
	str = json_string_value(val);
	bin = jwt_base64uri_decode(str, &len);

	OSSL_PARAM_BLD_push_octet_string(build, ossl_name, bin, len);

	return bin;
}

static int pctx_to_pem(EVP_PKEY_CTX *pctx, OSSL_PARAM *params,
		       jwk_item_t *item, int priv)
{
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	char *src = NULL, *dest = NULL;
	long len;
	int ret = -1;

	ret = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PRIVATE_KEY, params);

	if (ret <= 0 || pkey == NULL) {
		jwks_write_error(item, "Unable to create PEM from pkey");
		goto cleanup_pem;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		jwks_write_error(item, "Unable to allocate memory for PEM BIO");
		goto cleanup_pem;
	}

	if (priv)
		ret = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
	else
		ret = PEM_write_bio_PUBKEY(bio, pkey);

	if (!ret) {
		jwks_write_error(item, "Internal error converting key to PEM");
		goto cleanup_pem;
	}

	len = BIO_get_mem_data(bio, &src);
	dest = jwt_malloc(len + 1);
	if (dest == NULL) {
		jwks_write_error(item, "Error allocating memory for PEM");
		goto cleanup_pem;
	}

	memcpy(dest, src, len);
	dest[len] = '\0';
	item->pem = dest;
	ret = 0;

cleanup_pem:
	EVP_PKEY_free(pkey);
	BIO_free(bio);

	return ret;
}

/* For EdDSA keys (EDDSA) */
int process_eddsa_jwk(json_t *jwk, jwk_item_t *item)
{
	unsigned char *pub_bin = NULL, *priv_bin = NULL;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *build = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	json_t *x, *d;
	int priv = 0;
	int ret = -1;

	/* EdDSA only need one or the other. */
	x = json_object_get(jwk, "x");
	d = json_object_get(jwk, "d");

	if (x == NULL && d == NULL) {
		jwks_write_error(item, "Need an 'x' or 'd' component and found neither");
		goto cleanup_eddsa;
	}

	if (d != NULL)
		priv = 1;
	
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
	if (pctx == NULL) {
		jwks_write_error(item, "Error creating pkey context");
		goto cleanup_eddsa;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		jwks_write_error(item, "Error starting pkey init from data");
		goto cleanup_eddsa;
	}

	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		jwks_write_error(item, "Error allocating params build");
		goto cleanup_eddsa;
	}

	if (!priv) {
		pub_bin = set_one_octet(build, OSSL_PKEY_PARAM_PUB_KEY, x);
		if (pub_bin == NULL) {
			jwks_write_error(item, "Error parsing pub key");
			goto cleanup_eddsa;
		}
	} else {
		priv_bin = set_one_octet(build, OSSL_PKEY_PARAM_PRIV_KEY, d);
		if (priv_bin == NULL) {
			jwks_write_error(item, "Error parsing private key");
			goto cleanup_eddsa;
		}
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		jwks_write_error(item, "Error creating build params");
		goto cleanup_eddsa;
	}

	/* Create PEM from params */
	ret = pctx_to_pem(pctx, params, item, priv);

cleanup_eddsa:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	EVP_PKEY_CTX_free(pctx);
	jwt_freemem(pub_bin);
	jwt_freemem(priv_bin);

	return ret;
}

/* For RSA keys (RS256, RS384, RS512). Also works for RSA-PSS
 * (PS256, PS384, PS512) */
int process_rsa_jwk(json_t *jwk, jwk_item_t *item)
{
	OSSL_PARAM_BLD *build = NULL;
	json_t *n, *e, *d, *p, *q, *dp, *dq, *qi, *alg;
	BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL,
		*bn_q = NULL, *bn_dp = NULL, *bn_dq = NULL, *bn_qi = NULL;
	int is_rsa_pss = 0, priv = 0, ret = -1;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	const char *alg_str = NULL;

	alg = json_object_get(jwk, "alg");
	n = json_object_get(jwk, "n");
	e = json_object_get(jwk, "e");
	d = json_object_get(jwk, "d");
	p = json_object_get(jwk, "p");
	q = json_object_get(jwk, "q");
	dp = json_object_get(jwk, "dp");
	dq = json_object_get(jwk, "dq");
	qi = json_object_get(jwk, "qi");

	if (n == NULL || e == NULL) {
		jwks_write_error(item,
			"Missing required RSA component: n or e");
		goto cleanup_rsa;
	}

	/* Check alg to see if we can sniff RSA vs RSA-PSS */
	if (alg) {
		alg_str = json_string_value(alg);

		if (alg_str[0] == 'P')
			is_rsa_pss = 1;
	}

	/* Priv vs PUB */
	if (d && p && q && dp && dq && qi) {
		priv = 1;
	} else if (!d && !p && !q && !dp && !dq && !qi) {
		priv = 0;
	} else {
		jwks_write_error(item,
			"Some priv key components exist, but some are missing");
		goto cleanup_rsa;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, is_rsa_pss ? "RSA-PSS" : "RSA",
					  NULL);
	if (pctx == NULL) {
		jwks_write_error(item, "Error creating pkey context");
		goto cleanup_rsa;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		jwks_write_error(item, "Error preparing conrtext for data");
		goto cleanup_rsa;
	}

	/* Set params */
	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		jwks_write_error(item, "Error creating param build");
		goto cleanup_rsa;
	}

	bn_n = set_one_bn(build, OSSL_PKEY_PARAM_RSA_N, n);
	bn_e = set_one_bn(build, OSSL_PKEY_PARAM_RSA_E, e);
	if (!bn_n || !bn_e) {
		jwks_write_error(item, "Error decoding pub components");
		goto cleanup_rsa;
	}

	if (priv) {
		bn_d = set_one_bn(build, OSSL_PKEY_PARAM_RSA_D, d);
		bn_p = set_one_bn(build, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
		bn_q = set_one_bn(build, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
		bn_dp = set_one_bn(build, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp);
		bn_dq = set_one_bn(build, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq);
		bn_qi = set_one_bn(build, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi);
		if (!bn_d || !bn_p || !bn_q || !bn_dp || !bn_dq || !bn_qi) {
			jwks_write_error(item, "Error decoding priv components");
			goto cleanup_rsa;
		}
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		jwks_write_error(item, "Error building params");
		goto cleanup_rsa;
	}

	/* Create PEM from params */
	ret = pctx_to_pem(pctx, params, item, priv);

cleanup_rsa:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	EVP_PKEY_CTX_free(pctx);

	BN_free(bn_n);
	BN_free(bn_e);
	BN_free(bn_d);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_dp);
	BN_free(bn_dq);
	BN_free(bn_qi);

	return ret;
}

/* For EC Keys (ES256, ES384, ES512) */
int process_ec_jwk(json_t *jwk, jwk_item_t *item)
{
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *build = NULL;
	json_t *crv, *x, *y, *d;
	EVP_PKEY_CTX *pctx = NULL;
	const char *crv_str;
	BIGNUM *bn = NULL;
	int priv = 0, ret = -1;
	void *pub_key = NULL;

	crv = json_object_get(jwk, "crv");
	x = json_object_get(jwk, "x");
	y = json_object_get(jwk, "y");
	d = json_object_get(jwk, "d");

	/* Check the minimal for pub key */
	if (crv == NULL || x == NULL || y == NULL) {
		jwks_write_error(item, "Missing one of crv, x, or y for pub key");
		goto cleanup_ec;
	}

	crv_str = json_string_value(crv);

	/* Only private keys contain this field */
	if (d != NULL)
		priv = 1;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL) {
		jwks_write_error(item, "Error creating pkey context");
		goto cleanup_ec;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		jwks_write_error(item, "Error preparing context for data");
		goto cleanup_ec;
	}

	/* Set params */
	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		jwks_write_error(item, "Error allocating param build");
		goto cleanup_ec;
	}

	set_one_string(build, OSSL_PKEY_PARAM_GROUP_NAME, crv);
	pub_key = set_ec_pub_key(build, x, y, crv_str);
	if (pub_key == NULL) {
		jwks_write_error(item, "Error generating pub key from components");
		goto cleanup_ec;
	}

	if (priv) {
		bn = set_one_bn(build, OSSL_PKEY_PARAM_PRIV_KEY, d);
		if (bn == NULL) {
			jwks_write_error(item, "Error parsing component d");
			goto cleanup_ec;
		}
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		jwks_write_error(item, "Error build params");
		goto cleanup_ec;
	}

	/* Create PEM from params */
	ret = pctx_to_pem(pctx, params, item, priv);

cleanup_ec:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	OPENSSL_free(pub_key);
	EVP_PKEY_CTX_free(pctx);
	BN_free(bn);

	return ret;
}
