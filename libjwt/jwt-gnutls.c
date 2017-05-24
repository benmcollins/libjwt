/* Copyright (C) 2017 Nicolas Mora <mail@babelouest.org>
	 This file is part of the JWT C Library

	 This library is free software; you can redistribute it and/or
	 modify it under the terms of the GNU Lesser General Public
	 License as published by the Free Software Foundation; either
	 version 2.1 of the License, or (at your option) any later version.

	 This library is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
	 Lesser General Public License for more details.

	 You should have received a copy of the GNU Lesser General Public
	 License along with the JWT Library; if not, see
	 <http://www.gnu.org/licenses/>.	*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jansson.h>

#include <jwt.h>

#include "jwt-private.h"
#include "b64.h"
#include "config.h"

/**
 * libjwt encryption/decryption function definitions
 */
int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len, const char *str) {
	int alg;
	
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
    break;
	}
	
	*len = gnutls_hmac_get_len(alg);
	(*out) = malloc(*len);
	if (*out == NULL) {
		return ENOMEM;
	}
	
	return !gnutls_hmac_fast(alg, jwt->key, jwt->key_len, str, strlen(str), (*out))?0:EINVAL;
}

int jwt_verify_sha_hmac(jwt_t *jwt, const char *head, const char *sig) {
	char * sig_check, * buf = NULL;
	unsigned int len;
	int res, buf_len;
	base64_encodestate state;
	
	if (!jwt_sign_sha_hmac(jwt, &sig_check, &len, head)) {
		buf = alloca(len * 2);
		jwt_base64_init_encodestate(&state);
		buf_len = jwt_base64_encode_block(sig_check, len, buf, &state);
		buf_len += jwt_base64_encode_blockend(buf + buf_len, &state);
		buf[buf_len] = '\0';

		jwt_base64uri_encode(buf);
		res = !strcmp(sig, buf)?0:EINVAL;
		free(sig_check);
	} else {
		res = EINVAL;
	}
	return res;
}

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len, const char *str) {
	gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat = {(void*) str, strlen(str)}, sig_dat;
	int res = 0, pk_alg;
	int alg;
	
	switch (jwt->alg) {
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
  case JWT_ALG_ES256:
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
  default:
    return EINVAL;
    break;
	}
	
	/* Initialize signature process data */
	if (gnutls_x509_privkey_init(&key)) {
		res = ENOMEM;
		goto CLEAN_NONE;
	}
	
	if (gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
		res = EINVAL;
		goto CLEAN_KEY;
	}
	
	if (gnutls_privkey_init(&privkey)) {
		res = ENOMEM;
		goto CLEAN_KEY;
	}
	
	if (gnutls_privkey_import_x509(privkey, key, 0)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
	if (pk_alg == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
	/* Sign data */
	if (gnutls_privkey_sign_data(privkey, alg, 0, &body_dat, &sig_dat)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
	(*out) = malloc(sig_dat.size);
	if (*out == NULL) {
		res = ENOMEM;
	}
	
	/* copy signature to out */
	memcpy((*out), sig_dat.data, sig_dat.size);
	*len = sig_dat.size;

	/* Clean and exit */
	gnutls_free(sig_dat.data);

CLEAN_PRIVKEY:
	gnutls_privkey_deinit(privkey);

CLEAN_KEY:
	gnutls_x509_privkey_deinit(key);

CLEAN_NONE:
	return res;
}

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64) {
	int sig_len;
	char * sig = jwt_b64_decode(sig_b64, &sig_len);
	gnutls_datum_t sig_dat = {(void*)sig, sig_len}, cert_dat = {(void*)jwt->key, jwt->key_len}, data = {(void*)head, strlen(head)};
	gnutls_pubkey_t pubkey;
	int alg;
	int res;
	
	switch (jwt->alg) {
  case JWT_ALG_RS256:
    alg = GNUTLS_DIG_SHA256;
    break;
  case JWT_ALG_RS384:
    alg = GNUTLS_DIG_SHA384;
    break;
  case JWT_ALG_RS512:
    alg = GNUTLS_DIG_SHA512;
    break;
  case JWT_ALG_ES256:
    alg = GNUTLS_DIG_SHA256;
    break;
  case JWT_ALG_ES384:
    alg = GNUTLS_DIG_SHA384;
    break;
  case JWT_ALG_ES512:
    alg = GNUTLS_DIG_SHA512;
    break;
  default:
    return EINVAL;
    break;
	}
	
	if (gnutls_pubkey_init(&pubkey)) {
		return EINVAL;
	}
	
	if (!gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM)) {
		res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
	} else {
		res = EINVAL;
	}
	gnutls_pubkey_deinit(pubkey);
	
	free(sig);
	return res;
}
