/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* OpenSSL implementation of the key2jwk_params op: parse a native key (PEM or
 * DER) into an EVP_PKEY and extract its raw components into the neutral
 * jwk_export_t. The common jwt_key2jwk() (jwk-export.c) base64url-encodes those
 * components into a JWK. This is the inverse of the JWK->EVP_PKEY parsing in
 * this backend's jwk-parse.c. */

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
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include "openssl/jwt-openssl.h"

/* Set the alg and crv for an EC key based on its size and group. Leaves both
 * empty on an unknown curve. */
static void ec_alg_type(EVP_PKEY *pkey, char *crv, char *alg)
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

/* Retrieve a single OSSL BIGNUM param as raw big-endian bytes and add it to the
 * export struct under @name. */
static void add_bn(EVP_PKEY *pkey, const char *ossl_param,
		   jwk_export_t *out, const char *name)
{
	BIGNUM *bn = NULL;
	unsigned char *bin;
	int len;

	if (!EVP_PKEY_get_bn_param(pkey, ossl_param, &bn) || bn == NULL)
		return; // LCOV_EXCL_LINE

	len = BN_num_bytes(bn);
	if (len <= 0) {
		// LCOV_EXCL_START
		BN_free(bn);
		return;
		// LCOV_EXCL_STOP
	}

	bin = jwt_malloc(len);
	if (bin == NULL) {
		// LCOV_EXCL_START
		BN_free(bn);
		return;
		// LCOV_EXCL_STOP
	}

	BN_bn2bin(bn, bin);
	BN_free(bn);

	jwk_export_add(out, name, bin, (size_t)len);
}

/* Retrieve a single OSSL octet param and add it to the export struct. */
static void add_octet(EVP_PKEY *pkey, const char *ossl_param,
		      jwk_export_t *out, const char *name)
{
	unsigned char buf[256];
	size_t len = 0;
	unsigned char *bin;

	if (!EVP_PKEY_get_octet_string_param(pkey, ossl_param, buf,
					     sizeof(buf), &len) || len == 0)
		return; // LCOV_EXCL_LINE

	bin = jwt_malloc(len);
	if (bin == NULL) {
		// LCOV_EXCL_START
		OPENSSL_cleanse(buf, len);
		return;
		// LCOV_EXCL_STOP
	}

	memcpy(bin, buf, len);
	OPENSSL_cleanse(buf, len);

	jwk_export_add(out, name, bin, len);
}

#if defined(LIBJWT_HAVE_ML_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L
/* Like add_octet, but for params too large for a fixed stack buffer: an
 * ML-DSA public key is 1312-2592 bytes. Probe the length, then heap-allocate. */
static void add_octet_big(EVP_PKEY *pkey, const char *ossl_param,
			  jwk_export_t *out, const char *name)
{
	unsigned char *bin;
	size_t len = 0;

	if (!EVP_PKEY_get_octet_string_param(pkey, ossl_param, NULL, 0, &len)
	    || len == 0)
		return; // LCOV_EXCL_LINE

	bin = jwt_malloc(len);
	if (bin == NULL)
		return; // LCOV_EXCL_LINE

	if (!EVP_PKEY_get_octet_string_param(pkey, ossl_param, bin, len, &len)
	    || len == 0) {
		// LCOV_EXCL_START
		jwt_freemem(bin);
		return;
		// LCOV_EXCL_STOP
	}

	jwk_export_add(out, name, bin, len);
}

/* For ML-DSA keys (ML-DSA-44/65/87), @rfc{9964}. The public key goes in
 * "pub"; a private key additionally carries the 32-byte FIPS-204 seed in
 * "priv". */
static void export_mldsa(EVP_PKEY *pkey, int priv, jwk_export_t *out)
{
	size_t seedlen = 0;

	add_octet_big(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, "pub");

	if (!priv)
		return;

	/* RFC 9964 represents an ML-DSA private key solely by its 32-byte
	 * FIPS-204 seed. A key that retains no seed (e.g. one imported from
	 * only the expanded private key) cannot be expressed as a private AKP
	 * JWK. Rather than emit a key that claims to be private but carries no
	 * private material, downgrade it to a public export. */
	if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_DSA_SEED,
					     NULL, 0, &seedlen) || seedlen == 0) {
		out->is_private = 0;
		return;
	}

	add_octet(pkey, OSSL_PKEY_PARAM_ML_DSA_SEED, out, "priv");
}
#endif /* LIBJWT_HAVE_ML_DSA */

/* For EC keys (ES256, ES384, ES512, ES256K) */
static void export_ec(EVP_PKEY *pkey, int priv, jwk_export_t *out)
{
	ec_alg_type(pkey, out->crv, out->alg);

	add_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_X, out, "x");
	add_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, out, "y");
	if (priv)
		add_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, "d");
}

/* For EdDSA keys (Ed25519, Ed448) */
static void export_eddsa(EVP_PKEY *pkey, int priv, jwk_export_t *out)
{
	if (priv)
		add_octet(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, "d");
	else
		add_octet(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, "x");
}

/* For RSA keys (RS256, RS384, RS512). Also works for RSA-PSS (PS256, PS384,
 * PS512) */
static void export_rsa(EVP_PKEY *pkey, int priv, jwk_export_t *out)
{
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_N, out, "n");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_E, out, "e");

	if (!priv)
		return;

	add_bn(pkey, OSSL_PKEY_PARAM_RSA_D, out, "d");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, out, "p");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, out, "q");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, out, "dp");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, out, "dq");
	add_bn(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, out, "qi");
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

JWT_NO_EXPORT
int openssl_key2jwk_params(const char *key, size_t len, jwk_export_t *out)
{
	EVP_PKEY *pkey;
	BIO *bio;
	int priv = 0;

	bio = BIO_new_mem_buf(key, (int)len);
	if (bio == NULL)
		return 1; // LCOV_EXCL_LINE

	pkey = read_pkey(bio, &priv);
	BIO_free(bio);

	/* Not a parseable key; the common code may try the HMAC fallback. */
	if (pkey == NULL)
		return 1;

	out->is_private = priv;

#if defined(LIBJWT_HAVE_ML_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L
	/* ML-DSA keys are provider-native and report no base id (0), so they
	 * are matched by type name rather than in the switch below. */
	{
		const char *tn = EVP_PKEY_get0_type_name(pkey);

		if (tn != NULL && (!strcmp(tn, "ML-DSA-44") ||
				   !strcmp(tn, "ML-DSA-65") ||
				   !strcmp(tn, "ML-DSA-87"))) {
			out->kty = JWK_KEY_TYPE_AKP;
			strcpy(out->alg, tn);
			export_mldsa(pkey, priv, out);
			EVP_PKEY_free(pkey);
			return 0;
		}
	}
#endif

	switch (EVP_PKEY_get_base_id(pkey)) {
	case EVP_PKEY_RSA:
		out->kty = JWK_KEY_TYPE_RSA;
		export_rsa(pkey, priv, out);
		break;

	case EVP_PKEY_EC:
		out->kty = JWK_KEY_TYPE_EC;
		export_ec(pkey, priv, out);
		break;

	case EVP_PKEY_ED25519:
		out->kty = JWK_KEY_TYPE_OKP;
		strcpy(out->crv, "Ed25519");
		strcpy(out->alg, "EdDSA");
		export_eddsa(pkey, priv, out);
		break;

	case EVP_PKEY_ED448:
		out->kty = JWK_KEY_TYPE_OKP;
		strcpy(out->crv, "Ed448");
		strcpy(out->alg, "EdDSA");
		export_eddsa(pkey, priv, out);
		break;

	case EVP_PKEY_RSA_PSS:
		/* An RSA-PSS key is only valid for the PS* algorithms. There is
		 * no in-key way to pick the hash, so default to PS256. */
		out->kty = JWK_KEY_TYPE_RSA;
		strcpy(out->alg, "PS256");
		export_rsa(pkey, priv, out);
		break;

	// LCOV_EXCL_START
	default:
		EVP_PKEY_free(pkey);
		return 1;
	// LCOV_EXCL_STOP
	}

	EVP_PKEY_free(pkey);

	return 0;
}
