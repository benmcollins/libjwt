/* Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <jwt.h>

/* https://github.com/zhicheng/base64 */
#include "base64.h"

#include "jwt-private.h"

int __append_str(char **buf, const char *str)
{
	char *new;

	if (str == NULL || str[0] == '\0')
		return 0;

	if (*buf == NULL) {
		new = jwt_malloc(strlen(str) + 1);
		if (new)
			new[0] = '\0';
	} else {
		new = jwt_realloc(*buf, strlen(*buf) + strlen(str) + 1);
	}

	if (new == NULL) {
		jwt_freemem(*buf);
		return 1;
	}

	strcat(new, str);

	*buf = new;

	return 0;
}

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
		return "EDDSA";
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
	else if (!jwt_strcmp(alg, "EDDSA"))
		return JWT_ALG_EDDSA;

	return JWT_ALG_INVAL;
}

void jwt_scrub_key(jwt_t *jwt)
{
	if (jwt->config.key) {
		/* Overwrite it so it's gone from memory. */
		memset(jwt->config.key, 0, jwt->config.key_len);

		jwt_freemem(jwt->config.key);
	}

	/* We do not claim to handle memory for this */
	jwt->config.jw_key = NULL;

	jwt->config.key_len = 0;
	jwt->alg = JWT_ALG_NONE;
}

jwt_t *jwt_create(jwt_config_t *config)
{
	jwt_t *new = NULL;
	jwt_alg_t alg = config->alg;
	int ret;

	/* We require a config, otherwise call jwt_new() */
	if (config == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* Make sure alg is sane */
	if (alg < JWT_ALG_NONE || alg >= JWT_ALG_INVAL) {
		errno = EINVAL;
		return NULL;
	}

	/* If we have a jwt_item_t, make sure either the config or the key
	 * has an alg, and sync them up. */
        if (alg == JWT_ALG_NONE && config && config->jw_key) {
		if (config->jw_key->alg == JWT_ALG_NONE) {
			/* Invalid request */
			errno = EINVAL;
			return NULL;
		}
		alg = config->jw_key->alg;
	}

	if (alg == JWT_ALG_NONE) {
		/* NONE should not have any keys */
		if (config->jw_key || config->key || config->key_len) {
	                errno = EINVAL;
			return NULL;
		}
	} else {
		if (config->jw_key) {
			if (config->key || config->key_len) {
				/* Cannot have both key and jw_key */
				errno = EINVAL;
				return NULL;
			}
			if (config->jw_key->alg != JWT_ALG_NONE &&
			    alg != config->jw_key->alg) {
				/* Mismatch */
				errno = EINVAL;
				return NULL;
			}
		} else if (!config->key || !config->key_len) {
			/* Must have both of these */
			errno = EINVAL;
			return NULL;
		}
	}

	ret = jwt_new(&new);
	if (ret)
		return NULL;

	if (config->key) {
		new->config.key_len = config->key_len;
		new->config.key = jwt_malloc(new->config.key_len);
		if (new->config.key == NULL) {
			errno = ENOMEM;
			jwt_freep(&new);
		} else {
			memcpy(new->config.key, config->key, config->key_len);
		}
	} else {
		new->config.jw_key = config->jw_key;
	}

	if (new)
		new->alg = alg;

	return new;
}

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, const unsigned char *key, int len)
{
	/* No matter what happens here, we do this. */
	jwt_scrub_key(jwt);

	if (alg < JWT_ALG_NONE || alg >= JWT_ALG_INVAL)
		return EINVAL;

	switch (alg) {
	case JWT_ALG_NONE:
		if (key || len)
			return EINVAL;
		break;

	default:
		if (!key || len <= 0)
			return EINVAL;

		jwt->config.key = jwt_malloc(len);
		if (!jwt->config.key)
			return ENOMEM; // LCOV_EXCL_LINE

		memcpy(jwt->config.key, key, len);
	}

	jwt->alg = alg;
	jwt->config.key_len = len;

	return 0;
}

jwt_alg_t jwt_get_alg(const jwt_t *jwt)
{
	if (jwt == NULL)
		return JWT_ALG_INVAL;

	return jwt->alg;
}

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = jwt_malloc(sizeof(jwt_t));
	if (!*jwt)
		return ENOMEM; // LCOV_EXCL_LINE

	memset(*jwt, 0, sizeof(jwt_t));

	(*jwt)->grants = json_object();
	if (!(*jwt)->grants) {
		// LCOV_EXCL_START
		jwt_freep(jwt);
		return ENOMEM;
		// LCOV_EXCL_STOP
	}

	(*jwt)->headers = json_object();
	if (!(*jwt)->headers) {
		// LCOV_EXCL_START
		jwt_freep(jwt);
		return ENOMEM;
		// LCOV_EXCL_STOP
	}

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	jwt_scrub_key(jwt);

	json_decref(jwt->grants);
	json_decref(jwt->headers);

	memset(jwt, 0, sizeof(*jwt));

	jwt_freemem(jwt);
}

jwt_t *jwt_dup(jwt_t *jwt)
{
	jwt_t *new = NULL;

	if (!jwt) {
		errno = EINVAL;
		goto dup_fail;
	}

	errno = 0;

	new = jwt_malloc(sizeof(jwt_t));
	if (!new) {
		// LCOV_EXCL_START
		errno = ENOMEM;
		return NULL;
		// LCOV_EXCL_STOP
	}

	memset(new, 0, sizeof(jwt_t));

	/* We do not claim to handle memory for this */
	new->config.jw_key = jwt->config.jw_key;

	if (jwt->config.key_len) {
		new->alg = jwt->alg;
		new->config.key = jwt_malloc(jwt->config.key_len);
		if (!new->config.key) {
			// LCOV_EXCL_START
			errno = ENOMEM;
			goto dup_fail;
			// LCOV_EXCL_STOP
		}
		memcpy(new->config.key, jwt->config.key, jwt->config.key_len);
		new->config.key_len = jwt->config.key_len;
	}

	new->grants = json_deep_copy(jwt->grants);
	if (!new->grants)
		errno = ENOMEM; // LCOV_EXCL_LINE

	new->headers = json_deep_copy(jwt->headers);
	if (!new->headers)
		errno = ENOMEM; // LCOV_EXCL_LINE

dup_fail:
	if (errno)
		jwt_freep(&new);

	return new;
}

const char *get_js_string(const json_t *js, const char *key)
{
	const char *val = NULL;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		if (json_is_string(js_val))
			val = json_string_value(js_val);
		else
			errno = EINVAL;
	} else {
		errno = ENOENT;
	}

	return val;
}

long get_js_int(const json_t *js, const char *key)
{
	long val = -1;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		if (json_is_integer(js_val))
			val = (long)json_integer_value(js_val);
		else
			errno = EINVAL;
	} else {
		errno = ENOENT;
	}

	return val;
}

int get_js_bool(const json_t *js, const char *key)
{
	int val = -1;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		switch (json_typeof(js_val)) {
		case JSON_TRUE:
			val = 1;
			break;
		case JSON_FALSE:
			val = 0;
			break;
		default:
			errno = EINVAL;
		}
	} else {
		errno = ENOENT;
	}
	return val;
}

void *jwt_base64uri_decode(const char *src, int *ret_len)
{
	void *buf;
	char *new;
	int len, i, z;

	if (src == NULL || ret_len == NULL)
		return NULL; // Should really be an abort

	/* Decode based on RFC-4648 URI safe encoding. */
	len = (int)strlen(src);
	/* When reversing the URI cleanse, we can possibly add up
	 * to 3 '=' characters to replace the missing padding. */
	new = jwt_malloc(len + 4);
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
	z = 4 - (i % 4);
	if (z < 4) {
		while (z--)
			new[i++] = '=';
	}
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
		return -ENOMEM; // LCOV_EXCL_LINE

	/* First, a normal base64 encoding */
	len = base64_encode((const unsigned char *)plain, plain_len, dst);
	if (len <= 0) {
		jwt_freemem(dst);
		return 0;
	}

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
	*_dst = dst;

	return i;
}

static int __check_hmac(const jwt_t *jwt)
{
	int key_bits = 0;

	if (jwt->config.jw_key)
		key_bits = jwt->config.jw_key->bits;
	else
		key_bits = jwt->config.key_len * 8;

	if (key_bits < 256)
		return -1;

	switch (jwt->alg) {
	case JWT_ALG_HS256:
		if (key_bits >= 256)
			return 0;
		break;

	case JWT_ALG_HS384:
		if (key_bits >= 384)
			return 0;
		break;

	case JWT_ALG_HS512:
		if (key_bits >= 512)
			return 0;
		break;

	default:
		return -1;
	}

	return -1;
}

static int __check_key_bits(const jwt_t *jwt)
{
	int key_bits = 0;

	if (jwt->config.jw_key)
		key_bits = jwt->config.jw_key->bits;

	/* Ignore if we don't have it */
	if (key_bits == 0)
		return 0;

	switch (jwt->alg) {
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	case JWT_ALG_PS256:
	case JWT_ALG_PS384:
	case JWT_ALG_PS512:
		if (key_bits >= 2048)
			return 0;
		break;

	case JWT_ALG_EDDSA:
	case JWT_ALG_ES256K:
	case JWT_ALG_ES256:
		if (key_bits == 256)
			return 0;
		break;

	case JWT_ALG_ES384:
		if (key_bits == 384)
			return 0;
		break;

	case JWT_ALG_ES512:
		if (key_bits == 521)
			return 0;
		break;

	default:
		return -1;
	}

	return -1;
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
			return EINVAL;
		return jwt_ops->sign_sha_hmac(jwt, out, len, str, str_len);

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
			return EINVAL;
		return jwt_ops->sign_sha_pem(jwt, out, len, str, str_len);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

int jwt_verify_sig(jwt_t *jwt, const char *head, unsigned int head_len,
		   const char *sig)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return jwt_ops->verify_sha_hmac(jwt, head, head_len, sig);

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
		return jwt_ops->verify_sha_pem(jwt, head, head_len, sig);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

void jwt_config_init(jwt_config_t *config)
{
	memset(config, 0, sizeof(*config));
}
