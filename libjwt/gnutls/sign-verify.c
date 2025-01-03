/* Copyright (C) 2017 Nicolas Mora <mail@babelouest.org>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jwt.h>

#include "jwt-private.h"

/**
 * libjwt Cryptographic Signature/Verification function definitions
 */
static int gnutls_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	int alg;

	if (jwt->config.jw_key)
		return EINVAL;

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
	default:
		return EINVAL;
	}

	*len = gnutls_hmac_get_len(alg);
	*out = jwt_malloc(*len);
	if (*out == NULL)
		return ENOMEM;

	if (gnutls_hmac_fast(alg, jwt->config.key, jwt->config.key_len,
			     str, str_len, *out)) {
		jwt_freemem(*out);
		*out = NULL;
		return EINVAL;
	}

	return 0;
}

static int gnutls_verify_sha_hmac(jwt_t *jwt, const char *head,
				  unsigned int head_len, const char *sig)
{
	char *sig_check, *buf = NULL;
	unsigned int len;
	int ret;

	if (gnutls_sign_sha_hmac(jwt, &sig_check, &len, head, head_len))
		return EINVAL;

	ret = jwt_base64uri_encode(&buf, sig_check, len);
	if (ret <= 0 || buf == NULL)
		return -ret;

	ret = jwt_strcmp(sig, buf) ? EINVAL : 0;

	jwt_freemem(buf);
	jwt_freemem(sig_check);

	return ret;
}

static int gnutls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
			       const char *str, unsigned int str_len)
{
	/* For EC handling. */
	int r_padding = 0, s_padding = 0, r_out_padding = 0,
		s_out_padding = 0;
	size_t out_size;

	if (jwt->config.jw_key != NULL)
		return EINVAL;

	gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t key_dat = {
		jwt->config.key,
		jwt->config.key_len
	};
	gnutls_datum_t body_dat = {
		(unsigned char *)str,
		str_len
	};
	gnutls_datum_t sig_dat, r, s;
	int ret = 0, pk_alg;
	int alg, adj;

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
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_EDDSA_ED25519;
		break;

	default:
		return EINVAL;
	}

	/* Initialize signature process data */
	if (gnutls_x509_privkey_init(&key))
		return ENOMEM;

	if (gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
		ret = EINVAL;
		goto sign_clean_key;
	}

	if (gnutls_privkey_init(&privkey)) {
		ret = ENOMEM;
		goto sign_clean_key;
	}

	if (gnutls_privkey_import_x509(privkey, key, 0)) {
		ret = EINVAL;
		goto sign_clean_privkey;
	}

	if (pk_alg != gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
		ret = EINVAL;
		goto sign_clean_privkey;
	}

	/* XXX Get curve name for ES256K case and make sure it's secp256k1 */

	/* XXX Get EC curve bits and make sure it matches ES* alg type */

	/* Sign data */
	if (gnutls_privkey_sign_data(privkey, alg, 0, &body_dat, &sig_dat)) {
		ret = EINVAL;
		goto sign_clean_privkey;
	}

	if (pk_alg == GNUTLS_PK_EC) {
		/* Start EC handling. */
		if ((ret = gnutls_decode_rs_value(&sig_dat, &r, &s))) {
			ret = EINVAL;
			goto sign_clean_privkey;
		}

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
		if (*out == NULL) {
			ret = ENOMEM;
			goto sign_clean_privkey;
		}
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
		if (*out == NULL) {
			ret = ENOMEM;
			goto sign_clean_privkey;
		}

		/* Copy signature to out */
		memcpy(*out, sig_dat.data, sig_dat.size);
		*len = sig_dat.size;
	}

	/* Clean and exit */
	gnutls_free(sig_dat.data);

sign_clean_privkey:
	gnutls_privkey_deinit(privkey);

sign_clean_key:
	gnutls_x509_privkey_deinit(key);

	if (ret && *out) {
		jwt_freemem(*out);
		*out = NULL;
	}

	return ret;
}

static int gnutls_verify_sha_pem(jwt_t *jwt, const char *head,
				 unsigned int head_len, const char *sig_b64)
{
	gnutls_datum_t r, s;
	gnutls_datum_t cert_dat = {
		jwt->config.key,
		jwt->config.key_len
	};
	gnutls_datum_t data = {
		(unsigned char *)head,
		head_len
	};
	gnutls_datum_t sig_dat = { NULL, 0 };
	gnutls_pubkey_t pubkey;
	int alg, ret = 0, sig_len;
	unsigned char *sig = NULL;

	if (jwt->config.jw_key != NULL)
		return EINVAL;

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
		alg = GNUTLS_SIGN_EDDSA_ED25519;
		break;

	default:
		return EINVAL;
	}

	sig = (unsigned char *)jwt_base64uri_decode(sig_b64, &sig_len);

	if (sig == NULL)
		return EINVAL;

	if (gnutls_pubkey_init(&pubkey)) {
		ret = EINVAL;
		goto verify_clean_sig;
	}

	if ((ret = gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM))) {
		ret = EINVAL;
		goto verify_clean_pubkey;
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
			ret = EINVAL;
			goto verify_clean_pubkey;
		}

		if (gnutls_encode_rs_value(&sig_dat, &r, &s) ||
		    gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat))
			ret = EINVAL;

		if (sig_dat.data != NULL)
			gnutls_free(sig_dat.data);

		break;

	default:
		/* Use simple signature verification. */
		sig_dat.size = sig_len;
		sig_dat.data = sig;

		if (gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat))
			ret = EINVAL;
	}

verify_clean_pubkey:
	gnutls_pubkey_deinit(pubkey);

verify_clean_sig:
	jwt_freemem(sig);

	return ret;
}

int gnutls_process_eddsa(json_t *jwk, jwk_item_t *item);
int gnutls_process_rsa(json_t *jwk, jwk_item_t *item);
int gnutls_process_ec(json_t *jwk, jwk_item_t *item);
void gnutls_process_item_free(jwk_item_t *item);

/* Export our ops */
struct jwt_crypto_ops jwt_gnutls_ops = {
	.name			= "gnutls",
	.provider		= JWT_CRYPTO_OPS_GNUTLS,

	.sign_sha_hmac		= gnutls_sign_sha_hmac,
	.verify_sha_hmac	= gnutls_verify_sha_hmac,
	.sign_sha_pem		= gnutls_sign_sha_pem,
	.verify_sha_pem		= gnutls_verify_sha_pem,

	/* Needs to be implemented */
	.jwk_implemented	= 0,
	.process_eddsa		= gnutls_process_eddsa,
	.process_rsa		= gnutls_process_rsa,
	.process_ec		= gnutls_process_ec,
	.process_item_free	= gnutls_process_item_free,
};
