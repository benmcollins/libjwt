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

#include "jwt-private.h"

static json_t *jwt_base64uri_decode_to_json(char *src)
{
	json_t *js;
	char *buf;
	int len;

	buf = jwt_base64uri_decode(src, &len);

	if (buf == NULL)
		return NULL; // LCOV_EXCL_LINE

	buf[len] = '\0';

	js = json_loads(buf, 0, NULL);

	jwt_freemem(buf);

	return js;
}

static int jwt_parse_body(jwt_t *jwt, char *body)
{
	if (jwt->grants)
		json_decrefp(&(jwt->grants));

	jwt->grants = jwt_base64uri_decode_to_json(body);
	if (!jwt->grants)
		return EINVAL;

	return 0;
}

static int jwt_parse_head(jwt_t *jwt, char *head)
{
	const char *alg;

	if (jwt->headers)
		json_decrefp(&(jwt->headers));

	jwt->headers = jwt_base64uri_decode_to_json(head);
	if (!jwt->headers)
		return EINVAL;

	alg = get_js_string(jwt->headers, "alg");
	jwt->alg = jwt_str_alg(alg);
	if (jwt->alg >= JWT_ALG_INVAL)
		return EINVAL;

	return 0;
}

/**
 * @brief Smoke test to save the user from themselves.
 */
static int jwt_verify_alg(jwt_t *jwt, const void *key, const int key_len)
{
	int ret = 0;

	if (jwt->alg == JWT_ALG_NONE) {
		/* If the user gave us a key but the JWT has alg = none,
		 * then we shouldn't even proceed. */
		if (key || key_len)
			ret = EINVAL;
	} else if (!(key && (key_len > 0))) {
		/* If alg != none, then we should have a key to use */
		ret = EINVAL;
	}

	/* Releive ourselves of the burden of this secret. */
	if (ret)
		jwt_scrub_key(jwt);

	return ret;
}

static int jwt_parse(jwt_t **jwt, const char *token, unsigned int *len)
{
	char *head = NULL;
	char *body, *sig;
	int ret = EINVAL;

	head = jwt_strdup(token);

	if (!head)
		return ENOMEM; // LCOV_EXCL_LINE

	/* Find the components. */
	for (body = head; body[0] != '.'; body++) {
		if (body[0] == '\0')
			goto parse_done;
	}

	body[0] = '\0';
	body++;

	for (sig = body; sig[0] != '.'; sig++) {
		if (sig[0] == '\0')
			goto parse_done;
	}

	sig[0] = '\0';

	/* Now that we have everything split up, let's check out the
	 * header. */
	ret = jwt_new(jwt);
	if (ret)
		goto parse_done;

	if ((ret = jwt_parse_head((*jwt), head)))
		goto parse_done;

	ret = jwt_parse_body((*jwt), body);
parse_done:
	if (ret) {
		jwt_freep(jwt);
	} else {
		*len = sig - head;
	}

	jwt_freemem(head);

	return ret;
}

static int jwt_copy_key(jwt_t *jwt, const unsigned char *key, int key_len)
{
	int ret = 0;

	if (!key_len)
		return 0;

	/* Always allocate one extra byte. For PEM, it ensures against
	 * not having a nil at the end (although all crypto backends
	 * should honor length), and for binary keys, it wont hurt
	 * because we use key_len for those operations. */
	jwt->key = jwt_malloc(key_len + 1);
	if (jwt->key == NULL)
		return ENOMEM; // LCOV_EXCL_LINE

	jwt->key[key_len] = '\0';

	memcpy(jwt->key, key, key_len);
	jwt->key_len = key_len;

	return ret;
}

static int jwt_verify_complete(jwt_t **jwt, const unsigned char *key,
			       int key_len, const char *token,
			       unsigned int payload_len)
{
	int ret = EINVAL;

	/* Make sure things make sense when it comes to alg and keys */
	ret = jwt_verify_alg(*jwt, key, key_len);
	if (ret)
		goto decode_done;

	/* Now we keep it */
	ret = jwt_copy_key(*jwt, key, key_len);
	if (ret)
		goto decode_done;

	/* Check the signature, if needed. */
	if ((*jwt)->alg != JWT_ALG_NONE) {
		const char *sig = token + (payload_len + 1);
		ret = jwt_verify_sig(*jwt, token, payload_len, sig);
	}

decode_done:
	if (ret)
		jwt_freep(jwt);

	return ret;
}

// LCOV_EXCL_START
int jwt_decode(jwt_t **jwt, const char *token, const unsigned char *key,
	       int key_len)
{
	unsigned int payload_len;
	int ret;

	if (jwt == NULL)
		return EINVAL;

	*jwt = NULL;

	if ((ret = jwt_parse(jwt, token, &payload_len)))
		return ret;

	return jwt_verify_complete(jwt, key, key_len, token, payload_len);
}

int jwt_decode_2(jwt_t **jwt, const char *token, jwt_callback_t cb)
{
	JWT_CONFIG_DECLARE(key);
	int ret;
	unsigned int payload_len;

	if (jwt == NULL)
		return EINVAL;

	*jwt = NULL;

	ret = jwt_parse(jwt, token, &payload_len);
	if (ret)
		return ret;

	if (cb) {
		/* The previous code trusted the JWT alg too much. If it was
		 * NONE, then it wouldn't even bother calling the cb.
		 *
		 * We also had some test cases that called this func with no
		 * cb and exptected it to work. True, this code allowed for
		 * that. My gut tells me that should never have been the case.
		 *
		 * For one, the previous code didn't check for NULL, so if
		 * you got a key that wasn't alg == none, instant SEGV.
		 *
		 * However, since this func is getting deprecated, we'll
		 * just let that case be like calling jwt_decode()
		 */
		ret = cb(*jwt, &key);
	}

	if (ret) {
		jwt_freep(jwt);
		return ret;
	}

	return jwt_verify_complete(jwt, key.key, key.key_len, token,
				   payload_len);
}
// LCOV_EXCL_STOP

/*
 * If no callback then we act just like jwt_verify().
 *
 * If no config, but there is a callback, then we have to assume
 * you do not want us doing much for you.
 */
int jwt_verify_wcb(jwt_t **jwt, const char *token, jwt_config_t *config,
		   jwt_callback_t cb)
{
	unsigned int payload_len;
	int ret;

	if (jwt == NULL)
		return EINVAL;

	*jwt = NULL;

	/* Quick smoke test */
	if (cb == NULL && config) {
		if (config->alg == JWT_ALG_NONE) {
			if (config->key != NULL || config->key_len)
				return EINVAL;
		} else {
			if (config->key == NULL || !config->key_len)
				return EINVAL;
		}
	}

	/* First parsing pass */
	ret = jwt_parse(jwt, token, &payload_len);
	if (ret)
		return ret;

	/* If the user requested an alg, do checks */
	if (config && config->alg != JWT_ALG_NONE) {
		/* Mismatch or no signature */
		if ((config->alg != (*jwt)->alg) || !payload_len) {
			jwt_freep(jwt);
			return EINVAL;
		}
	}

	/* Let them handle it now. */
	if (cb) {
		ret = cb(*jwt, config);
		if (ret) {
			jwt_freep(jwt);
			return ret;
		}
	}

	/* Finish it up */
	return jwt_verify_complete(jwt,
		(config == NULL) ? NULL : config->key,
		(config == NULL) ? 0 : config->key_len,
		token, payload_len);
}

int jwt_verify(jwt_t **jwt, const char *token, jwt_config_t *config)
{
	return jwt_verify_wcb(jwt, token, config, NULL);
}
