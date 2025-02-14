/* Copyright (C) 2017 Nicolas Mora <mail@babelouest.org>
   Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jwt.h>

#include "jwt-private.h"

#include "jwt-gnutls.h"

/**
 * libjwt Cryptographic Signature/Verification function definitions
 */
static int gnutls_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	int alg;
	void *key;
	size_t key_len;

	key = jwt->key->oct.key;
	key_len = jwt->key->oct.len;

	switch (jwt->alg) {
	case JWT_ALG_HS256:
		alg = GNUTLS_DIG_SHA256;
		break;
	case JWT_ALG_HS384:
		alg = GNUTLS_DIG_SHA384;
		break;
	case JWT_ALG_HS512:
		alg = GNUTLS_DIG_SHA512;
		break;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	*len = gnutls_hmac_get_len(alg);
	*out = jwt_malloc(*len);
	if (*out == NULL)
		return 1; // LCOV_EXCL_LINE

	if (gnutls_hmac_fast(alg, key, key_len, str, str_len, *out)) {
		// LCOV_EXCL_START
		jwt_freemem(*out);
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

#define SIGN_ERROR(_msg) { jwt_write_error(jwt, "JWT[GnuTLS]: " _msg); goto sign_clean_privkey; }

static int gnutls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
			       const char *str, unsigned int str_len)
{
	/* For EC handling. */
	int r_padding = 0, s_padding = 0, r_out_padding = 0,
		s_out_padding = 0;
	gnutls_privkey_t privkey;
	size_t out_size;
	gnutls_datum_t sig_dat, r, s;
	gnutls_digest_algorithm_t alg;
	int pk_alg, flags = 0;
	unsigned int adj;

	if (gnutls_privkey_init(&privkey))
		SIGN_ERROR("Error initializing privkey"); // LCOV_EXCL_LINE

	if (jwt->alg == JWT_ALG_ES256K)
		SIGN_ERROR("ES256K not supported"); // LCOV_EXCL_LINE

	if (jwt->key->pem == NULL)
		SIGN_ERROR("No PEM to load"); // LCOV_EXCL_LINE

	gnutls_datum_t key_dat = {
		(unsigned char *)jwt->key->pem,
		strlen(jwt->key->pem)
	};
	gnutls_datum_t body_dat = {
		(unsigned char *)str,
		str_len
	};

	/* Try loading as a private key, and extracting the pubkey */
	if (gnutls_privkey_import_x509_raw(privkey, &key_dat,
					   GNUTLS_X509_FMT_PEM,
					   NULL, 0)) {
		SIGN_ERROR("Could not import private key"); // LCOV_EXCL_LINE
	}

	/* Initialize for checking later. */
	*out = NULL;

	switch (jwt->alg) {
	/* RSA */
	case JWT_ALG_RS256:
		alg = GNUTLS_DIG_SHA256;
		pk_alg = GNUTLS_PK_RSA;
		break;
	case JWT_ALG_RS384:
		alg = GNUTLS_DIG_SHA384;
		pk_alg = GNUTLS_PK_RSA;
		break;
	case JWT_ALG_RS512:
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_RSA;
		break;

	/* RSA-PSS */
	case JWT_ALG_PS256:
		alg = GNUTLS_DIG_SHA256;
		pk_alg = GNUTLS_PK_RSA_PSS;
		break;
	case JWT_ALG_PS384:
		alg = GNUTLS_DIG_SHA384;
		pk_alg = GNUTLS_PK_RSA_PSS;
		break;
	case JWT_ALG_PS512:
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_RSA_PSS;
		break;

	/* EC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		alg = GNUTLS_DIG_SHA256;
		pk_alg = GNUTLS_PK_EC;
		break;
	case JWT_ALG_ES384:
		alg = GNUTLS_DIG_SHA384;
		pk_alg = GNUTLS_PK_EC;
		break;
	case JWT_ALG_ES512:
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_EC;
		break;

	/* EdDSA */
	case JWT_ALG_EDDSA:
		pk_alg = gnutls_privkey_get_pk_algorithm(privkey, NULL);
		if (pk_alg == GNUTLS_PK_EDDSA_ED25519)
			alg = GNUTLS_DIG_SHA512;
		else if (pk_alg == GNUTLS_PK_EDDSA_ED448) {
			alg = GNUTLS_DIG_SHAKE_256;
		} else {
			SIGN_ERROR("Unknown EdDSA key"); // LCOV_EXCL_LINE
		}
		break;
	// LCOV_EXCL_START
	default:
		SIGN_ERROR("Unknown signing alg");
	// LCOV_EXCL_STOP
	}

	if (pk_alg == GNUTLS_PK_RSA_PSS) {
		int ck = gnutls_privkey_get_pk_algorithm(privkey, NULL);
		if (ck != GNUTLS_PK_RSA_PSS && ck != GNUTLS_PK_RSA)
			SIGN_ERROR("RSASSA-PSS alg mismatch"); // LCOV_EXCL_LINE

		flags |= GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
	} else if (pk_alg != gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
		SIGN_ERROR("Alg mismatch with signing key"); // LCOV_EXCL_LINE
	}

	if (gnutls_privkey_sign_data(privkey, alg, flags,
                                &body_dat, &sig_dat))
		SIGN_ERROR("Failed to sign token"); // LCOV_EXCL_LINE

	if (pk_alg == GNUTLS_PK_EC) {
		/* Start EC handling. */
		if (gnutls_decode_rs_value(&sig_dat, &r, &s))
			SIGN_ERROR("Error decoding EC key"); // LCOV_EXCL_LINE

		/* Check r and s size */
		if (jwt->alg == JWT_ALG_ES256 || jwt->alg == JWT_ALG_ES256K)
			adj = 32;
		if (jwt->alg == JWT_ALG_ES384)
			adj = 48;
		if (jwt->alg == JWT_ALG_ES512)
			adj = 66;

		if (r.size > adj)
			r_padding = r.size - adj;
		else if (r.size < adj)
			r_out_padding = adj - r.size;

		if (s.size > adj)
			s_padding = s.size - adj;
		else if (s.size < adj)
			s_out_padding = adj - s.size;

		out_size = adj << 1;

		*out = jwt_malloc(out_size);
		if (*out == NULL)
			SIGN_ERROR("Out of memory"); // LCOV_EXCL_LINE

		memset(*out, 0, out_size);

		memcpy(*out + r_out_padding, r.data + r_padding, r.size - r_padding);
		memcpy(*out + (r.size - r_padding + r_out_padding) + s_out_padding,
		       s.data + s_padding, (s.size - s_padding));

		*len = (r.size - r_padding + r_out_padding) +
			(s.size - s_padding + s_out_padding);
		gnutls_free(r.data);
		gnutls_free(s.data);
	} else {
		/* All others that aren't EC */
		*out = jwt_malloc(sig_dat.size);
		if (*out == NULL)
			SIGN_ERROR("Out of memory"); // LCOV_EXCL_LINE

		/* Copy signature to out */
		memcpy(*out, sig_dat.data, sig_dat.size);
		*len = sig_dat.size;
	}

	/* Clean and exit */
	gnutls_free(sig_dat.data);

sign_clean_privkey:
	gnutls_privkey_deinit(privkey);

	if (jwt->error)
		jwt_freemem(*out); // LCOV_EXCL_LINE

	return jwt->error;
}

#define VERIFY_ERROR(_msg) { jwt_write_error(jwt, "JWT[GnuTLS]: " _msg); goto verify_clean_sig; }

static int gnutls_verify_sha_pem(jwt_t *jwt, const char *head,
				 unsigned int head_len, unsigned char *sig,
				 int sig_len)
{
	gnutls_datum_t r, s;
	gnutls_datum_t data = {
		(unsigned char *)head,
		head_len
	};
	gnutls_datum_t sig_dat = { NULL, 0 };
	gnutls_pubkey_t pubkey;
	int alg, ret = 0;

	if (gnutls_pubkey_init(&pubkey))
		VERIFY_ERROR("Failed initializing pubkey"); // LCOV_EXCL_LINE

	if (jwt->key->pem == NULL)
		VERIFY_ERROR("No PEM to load"); // LCOV_EXCL_LINE

	gnutls_datum_t cert_dat = {
		(unsigned char *)jwt->key->pem,
		strlen(jwt->key->pem)
	};

	if (jwt->alg == JWT_ALG_ES256K)
		VERIFY_ERROR("ES256K not supported"); // LCOV_EXCL_LINE

	if (gnutls_pubkey_init(&pubkey))
		VERIFY_ERROR("Error initializing pubkey"); // LCOV_EXCL_LINE

	ret = gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM);
	if (ret) {
		gnutls_privkey_t privkey;

		/* Try loading as a private key, and extracting the pubkey.
		 * This is perfectly legit. A JWK can have a private key with
		 * key_ops of SIGN and VERIFY. */
		if (gnutls_privkey_init(&privkey))
			VERIFY_ERROR("Failed initializing privkey"); // LCOV_EXCL_LINE

		/* Try loading as a private key, and extracting the pubkey */
		if (gnutls_privkey_import_x509_raw(privkey, &cert_dat,
						   GNUTLS_X509_FMT_PEM,
						   NULL, 0)) {
			VERIFY_ERROR("Failed importing key"); // LCOV_EXCL_LINE
		}

		ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
		gnutls_privkey_deinit(privkey);

		if (ret)
			VERIFY_ERROR("Failed to import key"); // LCOV_EXCL_LINE
	}

	switch (jwt->alg) {
	/* RSA */
	case JWT_ALG_RS256:
		alg = GNUTLS_SIGN_RSA_SHA256;
		break;
	case JWT_ALG_RS384:
		alg = GNUTLS_SIGN_RSA_SHA384;
		break;
	case JWT_ALG_RS512:
		alg = GNUTLS_SIGN_RSA_SHA512;
		break;

	/* RSA-PSS */
	case JWT_ALG_PS256:
		alg = GNUTLS_SIGN_RSA_PSS_SHA256;
		break;
	case JWT_ALG_PS384:
		alg = GNUTLS_SIGN_RSA_PSS_SHA384;
		break;
	case JWT_ALG_PS512:
		alg = GNUTLS_SIGN_RSA_PSS_SHA512;
		break;

	/* EC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
		alg = GNUTLS_SIGN_ECDSA_SHA256;
		break;
	case JWT_ALG_ES384:
		alg = GNUTLS_SIGN_ECDSA_SHA384;
		break;
	case JWT_ALG_ES512:
		alg = GNUTLS_SIGN_ECDSA_SHA512;
		break;

	/* EdDSA */
	case JWT_ALG_EDDSA:
		alg = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
		if (alg == GNUTLS_PK_EDDSA_ED25519)
			alg = GNUTLS_SIGN_EDDSA_ED25519;
		else if (alg == GNUTLS_PK_EDDSA_ED448) {
			alg = GNUTLS_SIGN_EDDSA_ED448;
		} else {
			VERIFY_ERROR("Unknown EdDSA key type"); // LCOV_EXCL_LINE
		}
		break;
	// LCOV_EXCL_START
	default:
		VERIFY_ERROR("Unknown alg");
	// LCOV_EXCL_STOP
	}

	/* Rebuild signature using r and s extracted from sig when jwt->alg
	 * is ESxxx. */
	switch (jwt->alg) {
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		/* XXX Gotta be a better way. */
		if (sig_len == 64) {
			r.size = 32;
			r.data = sig;
			s.size = 32;
			s.data = sig + 32;
		} else if (sig_len == 96) {
			r.size = 48;
			r.data = sig;
			s.size = 48;
			s.data = sig + 48;
		} else if (sig_len == 132) {
			r.size = 66;
			r.data = sig;
			s.size = 66;
			s.data = sig + 66;
		} else {
			VERIFY_ERROR("Irregular sig_len for ECDHA"); // LCOV_EXCL_LINE
		}

		if (gnutls_encode_rs_value(&sig_dat, &r, &s) ||
		    gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat))
			ret = 1; // LCOV_EXCL_LINE

		if (sig_dat.data != NULL)
			gnutls_free(sig_dat.data);

		if (ret)
			VERIFY_ERROR("Could not encode R/S values for ECDHA"); // LCOV_EXCL_LINE
		break;

	default:
		/* Use simple signature verification. */
		sig_dat.size = sig_len;
		sig_dat.data = sig;

		if (gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat))
			VERIFY_ERROR("Failed to verify signature"); // LCOV_EXCL_LINE
	}

verify_clean_sig:
	gnutls_pubkey_deinit(pubkey);

	return ret;
}

/* Export our ops */
struct jwt_crypto_ops jwt_gnutls_ops = {
	.name			= "gnutls",
	.provider		= JWT_CRYPTO_OPS_GNUTLS,

	.sign_sha_hmac		= gnutls_sign_sha_hmac,
	.sign_sha_pem		= gnutls_sign_sha_pem,
	.verify_sha_pem		= gnutls_verify_sha_pem,

	/* Needs to be implemented */
	.jwk_implemented	= 1,
	.process_eddsa		= openssl_process_eddsa,
	.process_rsa		= openssl_process_rsa,
	.process_ec		= openssl_process_ec,
	.process_item_free	= openssl_process_item_free,
};
