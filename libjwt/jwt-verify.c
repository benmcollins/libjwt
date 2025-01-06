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
	*jwt = jwt_new();
	if (*jwt == NULL)
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

/* This is after parsing and possibly a user callback. */
static int __verify_config_post(const jwt_t *jwt, const jwt_config_t *config,
				unsigned int sig_len)
{
	/*
	 * Lots of cases to deal with.
	 *
	 * 1) If the user passed a jw_key:
	 *    - It's valid for jw_key.alg to be none (missing) (RFC-7517:4.4)
	 *    - If jw_key.alg is not none, it MUST match the JWT
	 * 2) If the user did not pass a key:
	 *    - Then jwt.alg MUST be none, and
	 *    - The sig_len MUST be zero
	 * 3) If jwt.alg is none then sig_len MUST be zero, regardless of (2)
	 * 4) If sig_len is 0, and the user passed a key or set an alg, we
	 *    fail
	 */

	/* No sig, but caller is expecting something (4) */
	if (!sig_len && (jwt->alg != JWT_ALG_NONE ||
			 (config && (config->alg != JWT_ALG_NONE ||
				     config->jw_key != NULL))))
		return EINVAL;

	/* Quick check on the JWT (avoids all kinds of CVE issues) (3) */
	if (sig_len && (jwt->alg == JWT_ALG_NONE || config == NULL))
		return EINVAL;

	/* Make sure caller isn't just peeking (use a cb for that) (2) */
	if (!config || !config->jw_key) {
		/* No key, but expecting one? */
		if (jwt->alg != JWT_ALG_NONE || sig_len)
			return EINVAL;

		/* If the user didn't pass a key, at this point we're safe. */
		return 0;
	}

	/* Validate jw_key (1) */
	if (jwt->alg != JWT_ALG_NONE &&
	    config->jw_key->alg != JWT_ALG_NONE &&
	    jwt->alg != config->jw_key->alg) {
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

	/* At this point, config is never NULL */
        (*jwt)->jw_key = config->jw_key;

	ret = jwt_verify_sig(*jwt, token, payload_len, sig);

decode_done:
	if (ret)
		jwt_freep(jwt);

	return ret;
}

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
