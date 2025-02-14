/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <jwt.h>

/* https://github.com/zhicheng/base64 */
#include "base64.h"

#include "jwt-private.h"

const char *jwt_alg_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	case JWT_ALG_HS384:
		return "HS384";
	case JWT_ALG_HS512:
		return "HS512";
	case JWT_ALG_RS256:
		return "RS256";
	case JWT_ALG_RS384:
		return "RS384";
	case JWT_ALG_RS512:
		return "RS512";
	case JWT_ALG_ES256:
		return "ES256";
	case JWT_ALG_ES256K:
		return "ES256K";
	case JWT_ALG_ES384:
		return "ES384";
	case JWT_ALG_ES512:
		return "ES512";
	case JWT_ALG_PS256:
		return "PS256";
	case JWT_ALG_PS384:
		return "PS384";
	case JWT_ALG_PS512:
		return "PS512";
	case JWT_ALG_EDDSA:
		return "EdDSA";
	default:
		return NULL;
	}
}

jwt_alg_t jwt_str_alg(const char *alg)
{
	if (alg == NULL)
		return JWT_ALG_INVAL;

	if (!jwt_strcmp(alg, "none"))
		return JWT_ALG_NONE;
	else if (!jwt_strcmp(alg, "HS256"))
		return JWT_ALG_HS256;
	else if (!jwt_strcmp(alg, "HS384"))
		return JWT_ALG_HS384;
	else if (!jwt_strcmp(alg, "HS512"))
		return JWT_ALG_HS512;
	else if (!jwt_strcmp(alg, "RS256"))
		return JWT_ALG_RS256;
	else if (!jwt_strcmp(alg, "RS384"))
		return JWT_ALG_RS384;
	else if (!jwt_strcmp(alg, "RS512"))
		return JWT_ALG_RS512;
	else if (!jwt_strcmp(alg, "ES256"))
		return JWT_ALG_ES256;
	else if (!jwt_strcmp(alg, "ES256K"))
		return JWT_ALG_ES256K;
	else if (!jwt_strcmp(alg, "ES384"))
		return JWT_ALG_ES384;
	else if (!jwt_strcmp(alg, "ES512"))
		return JWT_ALG_ES512;
	else if (!jwt_strcmp(alg, "PS256"))
		return JWT_ALG_PS256;
	else if (!jwt_strcmp(alg, "PS384"))
		return JWT_ALG_PS384;
	else if (!jwt_strcmp(alg, "PS512"))
		return JWT_ALG_PS512;
	else if (!jwt_strcmp(alg, "EdDSA"))
		return JWT_ALG_EDDSA;

	return JWT_ALG_INVAL;
}

JWT_NO_EXPORT
jwt_t *jwt_new(void)
{
	jwt_t *jwt = jwt_malloc(sizeof(*jwt));

	if (!jwt)
		return NULL; // LCOV_EXCL_LINE

	memset(jwt, 0, sizeof(*jwt));

	jwt->claims = json_object();
	jwt->headers = json_object();

	if (!jwt->claims || !jwt->headers)
		jwt_freep(&jwt); // LCOV_EXCL_LINE

	return jwt;
}

jwt_alg_t jwt_get_alg(const jwt_t *jwt)
{
	if (jwt == NULL)
		return JWT_ALG_INVAL;

	return jwt->alg;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	json_decref(jwt->claims);
	json_decref(jwt->headers);

	memset(jwt, 0, sizeof(*jwt));

	jwt_freemem(jwt);
}

void *jwt_base64uri_decode(const char *src, int *ret_len)
{
	void *buf;
	char *new;
	int len, i, z;

	if (src == NULL || ret_len == NULL)
		return NULL; // LCOV_EXCL_LINE
			     // Should really be an abort

	/* Decode based on RFC-4648 URI safe encoding. */
	len = (int)strlen(src);

	/* Validate length */
	z = (len % 4);
	switch (z) {
	case 0:
		/* No added padding */
		break;

	case 2:
		/* 2 added = for padding */
		break;

	case 3:
		/* 1 added = for padding */
		z = 1;
		break;

	default:
		/* Something bad */
		return NULL;
	}

	new = jwt_malloc(len + z + 1);
	if (!new)
		return NULL; // LCOV_EXCL_LINE

	for (i = 0; i < len; i++) {
		switch (src[i]) {
		case '-':
			new[i] = '+';
			break;
		case '_':
			new[i] = '/';
			break;
		default:
			new[i] = src[i];
		}
	}

	for (; z > 0; z--)
		new[i++] = '=';

	new[i] = '\0';
	len = i;

	/* Now we have a standard base64 encoded string. */
	buf = jwt_malloc(BASE64_DECODE_OUT_SIZE(len) + 1);
	if (buf == NULL) {
		// LCOV_EXCL_START
		jwt_freemem(new);
		return NULL;
		// LCOV_EXCL_STOP
	}

	*ret_len = base64_decode(new, len, buf);
	jwt_freemem(new);

	if (*ret_len <= 0)
		jwt_freemem(buf);

	return buf;
}

int jwt_base64uri_encode(char **_dst, const char *plain, int plain_len)
{
	int len, i;
	char *dst;

	len = BASE64_ENCODE_OUT_SIZE(plain_len);
	dst = jwt_malloc(len + 1);
	if (dst == NULL)
		return -1; // LCOV_EXCL_LINE
	*_dst = dst;

	/* First, a normal base64 encoding */
	len = base64_encode((const unsigned char *)plain, plain_len, dst);

	/* Now for the URI encoding */
	for (i = 0; i < len; i++) {
		switch (dst[i]) {
		case '+':
			dst[i] = '-';
			break;
		case '/':
			dst[i] = '_';
			break;
		case '=':
			dst[i] = '\0';
			break;
		}
	}

	/* Just in case there's no padding. */
	dst[i] = '\0';

	return i;
}

static int __check_hmac(jwt_t *jwt)
{
	int key_bits = jwt->key->bits;

	switch (jwt->alg) {
	case JWT_ALG_HS256:
		if (key_bits >= 256)
			return 0;
		jwt_write_error(jwt, "Key too short for HS256: %d bits",
				key_bits);
		break;

	case JWT_ALG_HS384:
		if (key_bits >= 384)
			return 0;
		jwt_write_error(jwt, "Key too short for HS384: %d bits",
				key_bits);
		break;

	case JWT_ALG_HS512:
		if (key_bits >= 512)
			return 0;
		jwt_write_error(jwt, "Key too short for HS512: %d bits",
				key_bits);
		break;
	// LCOV_EXCL_START
	default:
		return 1;
	// LCOV_EXCL_STOP
	}

	return 1;
}

static int __check_key_bits(jwt_t *jwt)
{
	int key_bits = jwt->key->bits;

	switch (jwt->alg) {
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	case JWT_ALG_PS256:
	case JWT_ALG_PS384:
	case JWT_ALG_PS512:
		if (key_bits >= 2048)
			return 0;
		jwt_write_error(jwt, "Key too short for RSA algs: %d bits",
				key_bits);
		break;

	case JWT_ALG_EDDSA:
		if (key_bits == 256 || key_bits == 456)
			return 0;
		jwt_write_error(jwt, "Key needs to be 256 or 456 bits: %d bits",
				key_bits);
		break;

	case JWT_ALG_ES256K:
	case JWT_ALG_ES256:
		if (key_bits == 256)
			return 0;
		jwt_write_error(jwt, "Key needs to be 256 bits: %d bits",
				key_bits);
		break;

	case JWT_ALG_ES384:
		if (key_bits == 384)
			return 0;
		jwt_write_error(jwt, "Key needs to be 384 bits: %d bits",
				key_bits);
		break;

	case JWT_ALG_ES512:
		if (key_bits == 521)
			return 0;
		jwt_write_error(jwt, "Key needs to be 521 bits: %d bits",
				key_bits);
		break;
	// LCOV_EXCL_START
	default:
		break;
	// LCOV_EXCL_STOP
	}

	return 1; // LCOV_EXCL_LINE
}

int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str,
	     unsigned int str_len)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		if (__check_hmac(jwt))
			return 1;
		if (jwt_ops->sign_sha_hmac(jwt, out, len, str, str_len)) {
			/* There's not really a way to induce failure here,
			 * and there's not really much of a chance this can fail
			 * other than an internal fatal error in the crypto
			 * library. */
			// LCOV_EXCL_START
			jwt_write_error(jwt, "Token failed signing");
			return 1;
			// LCOV_EXCL_STOP
		} else {
			return 0;
		}

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* RSA-PSS */
	case JWT_ALG_PS256:
	case JWT_ALG_PS384:
	case JWT_ALG_PS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:

	/* EdDSA */
	case JWT_ALG_EDDSA:
		if (__check_key_bits(jwt))
			return 1;
		if (jwt_ops->sign_sha_pem(jwt, out, len, str, str_len)) {
			jwt_write_error(jwt, "Token failed signing");
			return 1;
		} else {
			return 0;
		}

	/* You wut, mate? */
	// LCOV_EXCL_START
	default:
		jwt_write_error(jwt, "Unknown algorigthm");
		return 1;
	// LCOV_EXCL_STOP
	}
}

static int _verify_sha_hmac(jwt_t *jwt, const char *head,
			    unsigned int head_len, const char *sig)
{
	char_auto *res = NULL;
	char_auto *buf = NULL;
	unsigned int res_len;
	int ret;

	ret = jwt_sign(jwt, &res, &res_len, head, head_len);
	if (ret)
		return 1; // LCOV_EXCL_LINE

	ret = jwt_base64uri_encode(&buf, res, res_len);
	if (ret <= 0)
		return 1; // LCOV_EXCL_LINE

	return jwt_strcmp(buf, sig) ? 1 : 0;
}

jwt_t *jwt_verify_sig(jwt_t *jwt, const char *head, unsigned int head_len,
		      const char *sig_b64)
{
	int sig_len;
	unsigned char *sig = NULL;

	sig = jwt_base64uri_decode(sig_b64, &sig_len);

	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		if (_verify_sha_hmac(jwt, head, head_len, sig_b64))
			jwt_write_error(jwt, "Token failed verification");
		break;

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* RSA-PSS */
	case JWT_ALG_PS256:
	case JWT_ALG_PS384:
	case JWT_ALG_PS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:

	/* EdDSA */
	case JWT_ALG_EDDSA:
		if (__check_key_bits(jwt))
			break;

		sig = jwt_base64uri_decode(sig_b64, &sig_len);
		if (sig == NULL) {
			jwt_write_error(jwt, "Error decoding signature");
			break;
		}

		if (jwt_ops->verify_sha_pem(jwt, head, head_len, sig, sig_len))
			jwt_write_error(jwt, "Token failed verification");

		jwt_freemem(sig);
		break;

	/* You wut, mate? */
	// LCOV_EXCL_START
	default:
		jwt_write_error(jwt, "Unknown algorigthm");
	} // LCOV_EXCL_STOP

	return jwt;
}
