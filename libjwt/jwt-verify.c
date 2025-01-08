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

static int jwt_parse(jwt_t *jwt, const char *token, unsigned int *len)
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
	/* The easy out; insecure JWT, and the caller expects it. */
	if (config->alg == JWT_ALG_NONE && config->jw_key == NULL && !sig_len &&
			jwt->alg == JWT_ALG_NONE)
		return 0;

	/* The quick fail. The caller and JWT disagree. */
	if (config->alg != jwt->alg) {
		jwt_write_error(jwt, "JWT alg does not match expected value");
		return 1;
	}

	/* At this point, someone is expecting a sig and we also know the
	 * caller and the JWT token agree on the alg. */

	/* We require a key and a signature. */
	if (config->jw_key == NULL || !sig_len) {
		jwt_write_error(jwt, "JWT does not contain a signature");
		return 1;
	}

	/* If the key has an alg, it must match the caller. */
	if (config->jw_key->alg != JWT_ALG_NONE &&
	    config->jw_key->alg != config->alg) {
		jwt_write_error(jwt, "JWT alg does not much the key being used");
		return 1;
	}

	return 0;
}

static jwt_t *jwt_verify_complete(jwt_t *jwt, const jwt_config_t *config,
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
	jwt->jw_key = config->jw_key;

	return jwt_verify_sig(jwt, token, payload_len, sig);
}

/*
 * If no callback then we act just like jwt_verify().
 */
jwt_t *jwt_verify_wcb(const char *token, jwt_config_t *config,
		      jwt_callback_t cb)
{
	unsigned int payload_len;
	jwt_t *jwt = NULL;

	if (config == NULL)
		return NULL;

	jwt = jwt_new();
	if (jwt == NULL)
		return NULL;

	/* First parsing pass, error will be set for us */
	if (jwt_parse(jwt, token, &payload_len))
		return jwt;

	/* Let the user handle this and update config */
	if (cb && cb(jwt, config)) {
		jwt_write_error(jwt, "User callback returned error");
		return jwt;
	}

	/* Finish it up */
	return jwt_verify_complete(jwt, config, token, payload_len);
}

jwt_t *jwt_verify(const char *token, jwt_config_t *config)
{
	return jwt_verify_wcb(token, config, NULL);
}

#if 0
jwt_t *jwt_verify_jwks(jwk_set_t *jwk_set, const char *token)
{
	JWT_CONFIG_DECLARE(config);

	if (token == NULL || jwk_set == NULL)
		return NULL;

	*jwt = jwt_new();
	if (*jwt == NULL)
		return NULL;

	config.ctx = jwk_set;

	ret = jwt_parse(jwt, token, &payload_len);
	if (ret) {
		jwt_write_error(jwt, "Error parsing token");
		return jwt;
	}

	if (jwt->alg == JWT_ALG_NONE) {
		jwt_write_error(jwt, "Token does not have an 'alg' attribute");
		return jwt;
	}

	ret = 
}
#endif
