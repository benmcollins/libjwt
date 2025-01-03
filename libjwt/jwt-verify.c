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

static int jwt_copy_key(jwt_t *jwt, const jwt_config_t *config,
			const unsigned int sig_len)
{
	/* Whack */
	if ((config->key || config->key_len) && config->jw_key)
		return EINVAL;

	if (config->key && config->key_len) {
		char *buf;

		/* Always allocate one extra byte. For PEM, it ensures against
		 * not having a nil at the end (although all crypto backends
		 * should honor length), and for binary keys, it wont hurt
		 * because we use key_len for those operations. */
		buf = jwt_malloc(config->key_len + 1);
		if (buf == NULL)
			return ENOMEM; // LCOV_EXCL_LINE

		buf[config->key_len] = '\0';
		memcpy(buf, config->key, config->key_len);

		jwt->config.key = buf;
		jwt->config.key_len = config->key_len;
	} else if (config->jw_key) {
		jwt->config.jw_key = config->jw_key;
	} else if (sig_len) {
		/* We have a sig and no key */
		return EINVAL;
	}

	return 0;
}

/* This is after parsing and possibly a user callback. */
static int __verify_config_post(const jwt_t *jwt, const jwt_config_t *config,
				unsigned int sig_len)
{
	/*
	 * Lots of cases to deal with.
	 *
	 * 1) If the user passed a key/len pair:
	 *    - Then config.alg MUST be other than none, and
	 *    - The config.alg MUST match jwt.alg
	 * 2) If the user passed a jw_key:
	 *    - It's valid for jw_key.alg to be none (missing) (RFC-7517:4.4)
	 *    - If jw_key.alg is not none, it MUST match the JWT
	 * 3) The user SHOULD NOT pass both types, but we allow it. However,
	 *    checks for both keys MUST pass.
	 * 4) If the user did not pass a key of any kind:
	 *    - Then jwt.alg MUST be none, and
	 *    - The sig_len MUST be zero
	 * 5) If jwt.alg is none then sig_len MUST be zero, regardless of (4)
	 */

	/* Quick check on the JWT (avoids all kinds of CVE issues) (5) */
	if (jwt->alg == JWT_ALG_NONE && sig_len)
		return EINVAL;

	/* Make sure caller isn't just peeking (use a cb for that) (4) */
	if (!config || !(config->key || config->jw_key)) {
		/* No key, but expecting one? */
		if (jwt->alg != JWT_ALG_NONE || sig_len)
			return EINVAL;

		/* If the user didn't pass a key, at this point we're safe. */
		return 0;
	}

	/* Validate jw_key (2) */
	if (config->jw_key) {
		if (jwt->alg != JWT_ALG_NONE &&
		    config->jw_key->alg != JWT_ALG_NONE &&
		    jwt->alg != config->jw_key->alg) {
				return EINVAL;
		}
	}

	/* Validate key/len pair (1)  */
	if (config->key || config->key_len) {
		if (config->alg == JWT_ALG_NONE)
			return EINVAL;
		if (config->alg != jwt->alg)
			return EINVAL;
	}

	return 0;
}

static int jwt_verify_complete(jwt_t **jwt, const jwt_config_t *config,
			       const char *token, unsigned int payload_len)
{
	const char *sig;
	unsigned int sig_len;
	int ret = 0;

	sig = token + (payload_len + 1);
	sig_len = strlen(sig);

	/* Check for conflicts in user request and JWT */
	ret = __verify_config_post(*jwt, config, sig_len);
	if (ret)
		goto decode_done;

	/* After all the checks, if we don't have a sig, we can move on. */
	if (!sig_len)
		return 0;

	/* Preserve the key into jwt_t */
	ret = jwt_copy_key(*jwt, config, sig_len);
	if (ret)
		goto decode_done;

	ret = jwt_verify_sig(*jwt, token, payload_len, sig);

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
	JWT_CONFIG_DECLARE(config);
	int ret;

	if (jwt == NULL)
		return EINVAL;

	*jwt = NULL;

	if ((ret = jwt_parse(jwt, token, &payload_len)))
		return ret;

	config.key = key;
	config.key_len = key_len;

	return jwt_verify_complete(jwt, &config, token, payload_len);
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

	return jwt_verify_complete(jwt, &key, token, payload_len);
}
// LCOV_EXCL_STOP

/*
 * If no callback then we act just like jwt_verify().
 */
int jwt_verify_wcb(jwt_t **jwt, const char *token, jwt_config_t *config,
		   jwt_callback_t cb)
{
	unsigned int payload_len;
	int ret;

	if (jwt == NULL)
		return EINVAL;

	*jwt = NULL;

	/* First parsing pass */
	ret = jwt_parse(jwt, token, &payload_len);
	if (ret)
		return ret;

	/* Let the user handle this and update config */
	if (cb) {
		ret = cb(*jwt, config);
		if (ret) {
			jwt_freep(jwt);
			return ret;
		}
	}

	/* Finish it up */
	return jwt_verify_complete(jwt, config, token, payload_len);
}

int jwt_verify(jwt_t **jwt, const char *token, jwt_config_t *config)
{
	return jwt_verify_wcb(jwt, token, config, NULL);
}
