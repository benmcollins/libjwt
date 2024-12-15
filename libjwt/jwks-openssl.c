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
	unsigned char *bin_x, *bin_y;
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
		return NULL;

	bin_x = jwt_base64uri_decode(str_x, &len_x);
	bin_y = jwt_base64uri_decode(str_y, &len_y);
	if (bin_x == NULL || bin_y == NULL) {
		jwt_freemem(bin_x);
		jwt_freemem(bin_y);
		return NULL;
	}

	/* Convert to BN */
	x = BN_bin2bn(bin_x, len_x, NULL);
	y = BN_bin2bn(bin_y, len_y, NULL);

	if (x == NULL || y == NULL) {
		BN_free(x);
		BN_free(y);
		jwt_freemem(bin_x);
		jwt_freemem(bin_y);
		return NULL;
	}

	/* Create the EC group and point */
	/* TODO Add error checking here */
	nid = OBJ_sn2nid(curve_name);
	group = EC_GROUP_new_by_curve_name(nid);
	point = EC_POINT_new(group);
	EC_POINT_set_affine_coordinates(group, point, x, y, NULL);
	pub_key_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED,
					 &pub_key, NULL);

	EC_POINT_free(point);
	EC_GROUP_free(group);
	BN_free(x);
	BN_free(y);
	jwt_freemem(bin_x);
	jwt_freemem(bin_y);

	OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY, pub_key,
					 pub_key_len);

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
	bin = jwt_base64uri_decode(str, &len);

	if (bin == NULL || len <= 0)
		return NULL;

	bn = BN_bin2bn(bin, len, NULL);
	jwt_freemem(bin);

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

static int pkey_to_pem(EVP_PKEY *pkey, jwk_item_t *item, int priv)
{
	BIO *bio = BIO_new(BIO_s_mem());
	char *src, *dest;
	long len;
	int ret;

	if (priv)
		ret = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
	else
		ret = PEM_write_bio_PUBKEY(bio, pkey);

	EVP_PKEY_free(pkey);

	if (!ret) {
		BIO_free(bio);
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error converting key to PEM");
		item->error = 1;
		return -1;
	}

	len = BIO_get_mem_data(bio, &src);
	dest = jwt_malloc(len + 1);
	memcpy(dest, src, len);
	BIO_free(bio);
	dest[len] = '\0';
	item->pem = dest;

	return 0;
}

/* For EdDSA keys (EDDSA) */
int process_eddsa_jwk(json_t *jwk, jwk_item_t *item)
{
	unsigned char *pub_bin = NULL, *priv_bin = NULL;
	OSSL_PARAM *params;
	OSSL_PARAM_BLD *build;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;
	json_t *x, *d;
	int priv = 0;

	x = json_object_get(jwk, "x");
	d = json_object_get(jwk, "d");

	if (x == NULL)
		return -1;

	if (d != NULL)
		priv = 1;
	
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
	if (pctx == NULL)
		return -1;

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	build = OSSL_PARAM_BLD_new();

	pub_bin = set_one_octet(build, OSSL_PKEY_PARAM_PUB_KEY, x);
	if (priv)
		priv_bin = set_one_octet(build, OSSL_PKEY_PARAM_PRIV_KEY, d);

	params = OSSL_PARAM_BLD_to_param(build);

	/* Create EVP_PKEY from params */
	if (priv)
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PRIVATE_KEY, params);
	else
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	EVP_PKEY_CTX_free(pctx);
	jwt_freemem(pub_bin);
	jwt_freemem(priv_bin);

	if (pkey == NULL) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error creating JWK");
		item->error = 1;
	}

	return pkey_to_pem(pkey, item, priv);
}

/* For RSA keys (RS256, RS384, RS512). Also works for RSA-PSS
 * (PS256, PS384, PS512) */
int process_rsa_jwk(json_t *jwk, jwk_item_t *item)
{
	OSSL_PARAM_BLD *build;
	json_t *n, *e, *d, *p, *q, *dp, *dq, *qi, *alg;
	BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL,
		*bn_q = NULL, *bn_dp = NULL, *bn_dq = NULL, *bn_qi = NULL;
	int is_rsa_pss = 0, priv = 0;
	OSSL_PARAM *params;
	EVP_PKEY *pkey = NULL;
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
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Invalid JWK: missing required RSA components");
		item->error = 1;
		return -1;
	}

	/* Check alg to see if we can sniff RSA vs RSA-PSS */
	if (alg) {
		alg_str = json_string_value(alg);

		if (alg_str[0] == 'P')
			is_rsa_pss = 1;
	}

	/* Priv vs PUB */
	if (d != NULL) {
		if (!p || !q || !dp || !dq || !qi) {
			snprintf(item->error_msg, sizeof(item->error_msg),
				 "Invalid JWK: missing required RSA components");
			item->error = 1;
			return -1;
		}
		priv = 1;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, is_rsa_pss ? "RSA-PSS" : "RSA",
					  NULL);
	if (pctx == NULL) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error creating JWK");
		item->error = 1;
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error creating JWK");
		item->error = 1;
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	/* Set params */
	build = OSSL_PARAM_BLD_new();

	bn_n = set_one_bn(build, OSSL_PKEY_PARAM_RSA_N, n);
	bn_e = set_one_bn(build, OSSL_PKEY_PARAM_RSA_E, e);

	if (priv) {
		bn_d = set_one_bn(build, OSSL_PKEY_PARAM_RSA_D, d);
		bn_p = set_one_bn(build, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
		bn_q = set_one_bn(build, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
		bn_dp = set_one_bn(build, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp);
		bn_dq = set_one_bn(build, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq);
		bn_qi = set_one_bn(build, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi);
	}

	params = OSSL_PARAM_BLD_to_param(build);

	/* Create EVP_PKEY from params */
	if (priv)
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PRIVATE_KEY, params);
	else
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

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

	if (pkey == NULL) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error creating JWK");
		item->error = 1;
	}

	return pkey_to_pem(pkey, item, priv);
}

/* For EC Keys (ES256, ES384, ES512) */
int process_ec_jwk(json_t *jwk, jwk_item_t *item)
{
	OSSL_PARAM *params;
	OSSL_PARAM_BLD *build;
	json_t *crv, *x, *y, *d;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	const char *crv_str;
	BIGNUM *bn = NULL;
	int priv = 0;
	void *pub_key;

	crv = json_object_get(jwk, "crv");
	x = json_object_get(jwk, "x");
	y = json_object_get(jwk, "y");
	d = json_object_get(jwk, "d");

	/* Check the minimal for pub key */
	if (crv == NULL || x == NULL || y == NULL)
		return -1;

	crv_str = json_string_value(crv);

	/* Only private keys contain this field */
	if (d != NULL)
		priv = 1;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL)
		return -1;

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	/* Set params */
	build = OSSL_PARAM_BLD_new();

	set_one_string(build, OSSL_PKEY_PARAM_GROUP_NAME, crv);
	pub_key = set_ec_pub_key(build, x, y, crv_str);
	if (pub_key == NULL) {
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_BLD_free(build);
		return -1;
	}

	if (priv)
		bn = set_one_bn(build, OSSL_PKEY_PARAM_PRIV_KEY, d);

	params = OSSL_PARAM_BLD_to_param(build);

	/* Create EVP_PKEY from params */
	if (priv)
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PRIVATE_KEY, params);
	else
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	OPENSSL_free(pub_key);
	EVP_PKEY_CTX_free(pctx);
	BN_free(bn);

	if (pkey == NULL) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Internal error creating JWK");
		item->error = 1;
	}

	return pkey_to_pem(pkey, item, priv);
}
