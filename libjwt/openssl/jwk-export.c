/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Convert a native key (PEM, DER, or raw HMAC bytes) into one or more JWK
 * JSON objects. This is the inverse of the JWK->EVP_PKEY parsing in
 * jwk-parse.c, and is always implemented by OpenSSL (which is always linked),
 * regardless of which backend signs and verifies. The produced JSON is then
 * routed back through the normal jwks_load() machinery so the resulting
 * jwk_item_t is built exactly as for a parsed JWKS. */

#include <stdlib.h>
#include <string.h>

#include <openssl/opensslv.h>
#include <jwt.h>
#include "jwt-private.h"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "openssl/jwt-openssl.h"

/* Generate an RFC 4122 version 4 UUID string into the caller's buffer, which
 * must be at least 37 bytes. Returns 0 on success. */
static int uuidv4(char out[37])
{
	uint8_t b[16];

	if (RAND_bytes(b, sizeof(b)) != 1)
		return -1; // LCOV_EXCL_LINE

	/* version 4 and RFC 4122 variant */
	b[6] = (b[6] & 0x0F) | 0x40;
	b[8] = (b[8] & 0x3F) | 0x80;

	snprintf(out, 37,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

	return 0;
}

/* Set the alg and crv for an EC key based on its size and group. Leaves both
 * empty on an unknown curve. */
static void ec_alg_type(EVP_PKEY *pkey, char crv[32], char alg[32])
{
	char named_crv[32];
	const char *a = NULL, *c = NULL;
	size_t bits = 0;

	crv[0] = alg[0] = '\0';

	EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_BITS, &bits);
	EVP_PKEY_get_group_name(pkey, named_crv, sizeof(named_crv), NULL);

	switch (bits) {
	case 256:
		if (!strcmp(named_crv, "secp256k1")) {
			a = "ES256K";
			c = "secp256k1";
		} else {
			a = "ES256";
			c = "P-256";
		}
		break;
	case 384:
		a = "ES384";
		c = "P-384";
		break;
	case 521:
		a = "ES512";
		c = "P-521";
		break;
	}

	if (a == NULL || c == NULL)
		return; // LCOV_EXCL_LINE

	strcpy(crv, c);
	strcpy(alg, a);
}

/* Retrieve and b64url-encode a single OSSL BIGNUM param and add it to the JWK
 * as a string. */
static void get_one_bn(EVP_PKEY *pkey, const char *ossl_param,
		       jwt_json_t *jwk, const char *name)
{
	BIGNUM *bn = NULL;
	unsigned char *bin;
	char *b64;
	int len;

	if (!EVP_PKEY_get_bn_param(pkey, ossl_param, &bn) || bn == NULL)
		return; // LCOV_EXCL_LINE

	len = BN_num_bytes(bn);
	bin = OPENSSL_malloc(len);
	if (bin == NULL) {
		// LCOV_EXCL_START
		BN_free(bn);
		return;
		// LCOV_EXCL_STOP
	}

	BN_bn2bin(bn, bin);
	BN_free(bn);

	jwt_base64uri_encode(&b64, (char *)bin, len);
	OPENSSL_free(bin);
	jwt_json_obj_set(jwk, name, jwt_json_create_str(b64));
	jwt_freemem(b64);
}

/* Retrieve and b64url-encode a single OSSL octet param and add it to the JWK
 * as a string. */
static void get_one_octet(EVP_PKEY *pkey, const char *ossl_param,
			  jwt_json_t *jwk, const char *name)
{
	unsigned char buf[256];
	size_t len = 0;
	char *b64;

	if (!EVP_PKEY_get_octet_string_param(pkey, ossl_param, buf,
					     sizeof(buf), &len) || len == 0)
		return; // LCOV_EXCL_LINE

	jwt_base64uri_encode(&b64, (char *)buf, len);
	OPENSSL_cleanse(buf, len);
	jwt_json_obj_set(jwk, name, jwt_json_create_str(b64));
	jwt_freemem(b64);
}

/* For EC keys (ES256, ES384, ES512, ES256K) */
static void process_ec_key(EVP_PKEY *pkey, int priv, jwt_json_t *jwk)
{
	char alg[32], crv[32];

	ec_alg_type(pkey, crv, alg);

	if (alg[0])
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str(alg));
	if (crv[0])
		jwt_json_obj_set(jwk, "crv", jwt_json_create_str(crv));

	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_X, jwk, "x");
	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, jwk, "y");
	if (priv)
		get_one_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");
}

/* For EdDSA keys (Ed25519, Ed448) */
static void process_eddsa_key(EVP_PKEY *pkey, int priv, jwt_json_t *jwk)
{
	if (priv)
		get_one_octet(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");
	else
		get_one_octet(pkey, OSSL_PKEY_PARAM_PUB_KEY, jwk, "x");
}

/* For RSA keys (RS256, RS384, RS512). Also works for RSA-PSS
 * (PS256, PS384, PS512) */
static void process_rsa_key(EVP_PKEY *pkey, int priv, jwt_json_t *jwk)
{
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_N, jwk, "n");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_E, jwk, "e");

	if (!priv)
		return;

	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_D, jwk, "d");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, jwk, "p");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, jwk, "q");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, jwk, "dp");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, jwk, "dq");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, jwk, "qi");
}

/* For HMAC keys (treat the raw bytes as an "oct" key). The alg is guessed
 * from the key length. */
static void process_hmac_key(jwt_json_t *jwk, const unsigned char *key,
			     size_t len)
{
	char *b64;

	jwt_json_obj_set(jwk, "kty", jwt_json_create_str("oct"));

	jwt_base64uri_encode(&b64, (const char *)key, (int)len);
	jwt_json_obj_set(jwk, "k", jwt_json_create_str(b64));
	jwt_freemem(b64);

	if (len >= 32 && len < 48)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS256"));
	else if (len >= 48 && len < 64)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS384"));
	else if (len >= 64)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS512"));
}

/* Read an EVP_PKEY from a BIO. Tries, in order: PEM public, PEM private, DER
 * public (SubjectPublicKeyInfo), DER private (PKCS#8/traditional). Sets *priv
 * to 1 if a private key was read. Returns NULL if none parsed. */
static EVP_PKEY *read_pkey(BIO *bio, int *priv)
{
	EVP_PKEY *pkey;

	*priv = 0;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (pkey != NULL)
		return pkey;

	BIO_reset(bio);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (pkey != NULL) {
		*priv = 1;
		return pkey;
	}

	/* Not PEM, try DER. */
	BIO_reset(bio);
	pkey = d2i_PUBKEY_bio(bio, NULL);
	if (pkey != NULL)
		return pkey;

	BIO_reset(bio);
	pkey = d2i_PrivateKey_bio(bio, NULL);
	if (pkey != NULL)
		*priv = 1;

	return pkey;
}

/* Convert a single native key (in memory) to a JWK JSON object and append it
 * to the out_array. Returns 0 if a key (or HMAC fallback) was produced, or -1
 * if the input could not be parsed as any key. */
static int one_key_to_jwk(const char *key, size_t len, unsigned int flags,
			  jwt_json_t *out_array)
{
	EVP_PKEY *pkey = NULL;
	jwt_json_t *jwk, *ops;
	BIO *bio;
	int priv = 0;
	char kid[37];

	bio = BIO_new_mem_buf(key, (int)len);
	if (bio == NULL)
		return -1; // LCOV_EXCL_LINE

	pkey = read_pkey(bio, &priv);
	BIO_free(bio);

	/* Could not parse a key. Optionally fall back to HMAC. */
	if (pkey == NULL && !(flags & JWK_KEY_TRY_HMAC))
		return -1;

	jwk = jwt_json_create();
	if (jwk == NULL) {
		// LCOV_EXCL_START
		EVP_PKEY_free(pkey);
		return -1;
		// LCOV_EXCL_STOP
	}

	if (pkey != NULL && !priv) {
		jwt_json_obj_set(jwk, "use", jwt_json_create_str("sig"));
	} else {
		ops = jwt_json_create_arr();
		jwt_json_arr_append(ops, jwt_json_create_str("sign"));
		jwt_json_obj_set(jwk, "key_ops", ops);
	}

	if ((flags & JWK_KEY_GEN_KID) && uuidv4(kid) == 0)
		jwt_json_obj_set(jwk, "kid", jwt_json_create_str(kid));

	/* HMAC fallback for unparseable input. */
	if (pkey == NULL) {
		process_hmac_key(jwk, (const unsigned char *)key, len);
		jwt_json_arr_append(out_array, jwk);
		return 0;
	}

	switch (EVP_PKEY_get_base_id(pkey)) {
	case EVP_PKEY_RSA:
		jwt_json_obj_set(jwk, "kty", jwt_json_create_str("RSA"));
		process_rsa_key(pkey, priv, jwk);
		break;

	case EVP_PKEY_EC:
		jwt_json_obj_set(jwk, "kty", jwt_json_create_str("EC"));
		process_ec_key(pkey, priv, jwk);
		break;

	case EVP_PKEY_ED25519:
		jwt_json_obj_set(jwk, "kty", jwt_json_create_str("OKP"));
		jwt_json_obj_set(jwk, "crv", jwt_json_create_str("Ed25519"));
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("EdDSA"));
		process_eddsa_key(pkey, priv, jwk);
		break;

	case EVP_PKEY_ED448:
		jwt_json_obj_set(jwk, "kty", jwt_json_create_str("OKP"));
		jwt_json_obj_set(jwk, "crv", jwt_json_create_str("Ed448"));
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("EdDSA"));
		process_eddsa_key(pkey, priv, jwk);
		break;

	case EVP_PKEY_RSA_PSS:
		/* An RSA-PSS key is only valid for the PS* algorithms. There is
		 * no in-key way to pick the hash, so default to PS256. */
		jwt_json_obj_set(jwk, "kty", jwt_json_create_str("RSA"));
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("PS256"));
		process_rsa_key(pkey, priv, jwk);
		break;

	// LCOV_EXCL_START
	default:
		EVP_PKEY_free(pkey);
		jwt_json_releasep(&jwk);
		return -1;
	// LCOV_EXCL_STOP
	}

	EVP_PKEY_free(pkey);
	jwt_json_arr_append(out_array, jwk);

	return 0;
}

JWT_NO_EXPORT
int openssl_key2jwk(const char *key, size_t len, unsigned int flags,
		    jwt_json_t *out_array)
{
	return one_key_to_jwk(key, len, flags, out_array);
}
