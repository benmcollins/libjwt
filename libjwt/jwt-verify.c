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
	if (!jwt->grants) {
		jwt_write_error(jwt, "Error parsing body");
		return 1;
	}

	return 0;
}

static int jwt_parse_head(jwt_t *jwt, char *head)
{
	json_t *jalg;

	if (jwt->headers)
		json_decrefp(&(jwt->headers));

	jwt->headers = jwt_base64uri_decode_to_json(head);
	if (!jwt->headers) {
		jwt_write_error(jwt, "Error parsing header");
		return 1;
	}

	jwt->alg = JWT_ALG_NONE;

	jalg = json_object_get(jwt->headers, "alg");
	if (jalg && json_is_string(jalg)) {
		const char *alg = json_string_value(jalg);

		jwt->alg = jwt_str_alg(alg);

		if (jwt->alg >= JWT_ALG_INVAL) {
			jwt_write_error(jwt, "Invalid ALG: [%s]", alg);
			return 1;
		}
	}

	return 0;
}

int jwt_parse(jwt_t *jwt, const char *token, unsigned int *len)
{
	char_auto *head = NULL;
	char *body, *sig;

	head = jwt_strdup(token);

	if (!head) {
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
	}

	/* Find the components. */
	for (body = head; body[0] != '.'; body++) {
		if (body[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of header");
			return 1;
		}
	}

	body[0] = '\0';
	body++;

	for (sig = body; sig[0] != '.'; sig++) {
		if (sig[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of body");
			return 1;
		}
	}

	sig[0] = '\0';

	/* Now that we have everything split up, let's check out the
	 * header. */
	if (jwt_parse_head(jwt, head))
		return 1;

	if (jwt_parse_body(jwt, body))
		return 1;

	*len = sig - head;

	return 0;
}

/* This is after parsing and possibly a user callback. */
static int __verify_config_post(jwt_t *jwt, const jwt_config_t *config,
				unsigned int sig_len)
{
	if (!sig_len) {
		if (config->key || config->alg != JWT_ALG_NONE) {
			jwt_write_error(jwt,
				"Expected a signature, but JWT has none");
			return 1;
		}

		return 0;
	}

	/* Signature is known to be present from this point */
	if (config->key == NULL) {
		jwt_write_error(jwt,
			"JWT has signature, but no key was given");
		return 1;
	}

	/* Key is known to be given at this point */
	if (config->alg == JWT_ALG_NONE) {
		if (config->key->alg != jwt->alg) {
			jwt_write_error(jwt, "Key alg does not match JWT");
			return 1;
		}
	} else if (config->key->alg == JWT_ALG_NONE) {
		if (config->alg != jwt->alg) {
			jwt_write_error(jwt, "Config alg does not match JWT");
			return 1;
		}
	} else if (config->alg != config->key->alg) {
		jwt_write_error(jwt, "Config and key alg does not match");
		return 1;
	}

	return 0;
}

jwt_t *jwt_verify_complete(jwt_t *jwt, const jwt_config_t *config,
			   const char *token, unsigned int payload_len)
{
	const char *sig;
	unsigned int sig_len;

	sig = token + (payload_len + 1);
	sig_len = strlen(sig);

	/* Check for conflicts in user request and JWT */
	if (__verify_config_post(jwt, config, sig_len))
		return jwt;

	/* After all the checks, if we don't have a sig, we can move on. */
	if (!sig_len)
		return jwt;

	/* At this point, config is never NULL */
	jwt->key = config->key;

	return jwt_verify_sig(jwt, token, payload_len, sig);
}
