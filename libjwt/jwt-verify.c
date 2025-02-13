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

static int jwt_parse_payload(jwt_t *jwt, char *payload)
{
	if (jwt->claims)
		json_decrefp(&(jwt->claims));

	jwt->claims = jwt_base64uri_decode_to_json(payload);
	if (!jwt->claims) {
		jwt_write_error(jwt, "Error parsing payload");
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

		return 0;
	}

	return 1;
}

int jwt_parse(jwt_t *jwt, const char *token, unsigned int *len)
{
	char_auto *head = NULL;
	char *payload, *sig;
	int head_len = strlen(token) + 1;

	head = jwt_malloc(head_len);
	if (!head) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* head_len includes nil */
	memcpy(head, token, head_len);

	/* Find the components. */
	for (payload = head; payload[0] != '.'; payload++) {
		if (payload[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of header");
			return 1;
		}
	}

	payload[0] = '\0';
	payload++;

	for (sig = payload; sig[0] != '.'; sig++) {
		if (sig[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of payload");
			return 1;
		}
	}

	sig[0] = '\0';

	/* Now that we have everything split up, let's check out the
	 * header. */
	if (jwt_parse_head(jwt, head))
		return 1;

	if (jwt_parse_payload(jwt, payload))
		return 1;

	*len = sig - head;

	return 0;
}

static int __check_str_claim(jwt_t *jwt, jwt_claims_t claim, char *claim_str)
{
	jwt_checker_t *checker = jwt->checker;
	jwt_value_t jval;
	const char *str;
	jwt_value_error_t err;

	if (!(checker->c.claims & claim))
		return 0;

	str = jwt_checker_claim_get(checker, claim);
	if (str == NULL)
		return 1; // LCOV_EXCL_LINE
			  // Check above makes this nearly impossible to hit

	jwt_set_GET_STR(&jval, claim_str);
	err = jwt_claim_get(jwt, &jval);

	if (err != JWT_VALUE_ERR_NONE || strcmp(str, jval.str_val))
		return 1;

	return 0;
}

static jwt_claims_t __verify_claims(jwt_t *jwt)
{
	jwt_checker_t *checker = jwt->checker;
	jwt_value_t jval;
	time_t now = time(NULL);
	jwt_value_error_t err;
	jwt_claims_t failed = 0;

	/* expiration in past */
	if (checker->c.claims & JWT_CLAIM_EXP) {
		jwt_set_GET_INT(&jval, "exp");
		err = jwt_claim_get(jwt, &jval);

		if (err == JWT_VALUE_ERR_NONE) {
			if (jval.int_val <= (now - checker->c.exp)) {
				failed |= JWT_CLAIM_EXP;
			}
		} else if (err != JWT_VALUE_ERR_NOEXIST)
			failed |= JWT_CLAIM_EXP; // LCOV_EXCL_LINE
	}

	/* not valid before now */
	if (checker->c.claims & JWT_CLAIM_NBF) {
		jwt_set_GET_INT(&jval, "nbf");
		err = jwt_claim_get(jwt, &jval);

		if (err == JWT_VALUE_ERR_NONE) {
			if (jval.int_val > (now + checker->c.nbf)) {
				failed |= JWT_CLAIM_NBF;
			}
		} else if (err != JWT_VALUE_ERR_NOEXIST)
			failed |= JWT_CLAIM_NBF; // LCOV_EXCL_LINE
	}

	/* issuer doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_ISS, "iss"))
		failed |= JWT_CLAIM_ISS;

	/* subject doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_SUB, "sub"))
		failed |= JWT_CLAIM_SUB;

	/* audience doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_AUD, "aud"))
		failed |= JWT_CLAIM_AUD;

	return failed;
}

/* This is after parsing and possibly a user callback. */
static int __verify_config_post(jwt_t *jwt, const jwt_config_t *config,
				unsigned int sig_len)
{
	/* Yes, we do this before checking a signature. */
	if (__verify_claims(jwt)) {
		/* TODO Pass back the ORd list of claims failed. */
		jwt_write_error(jwt, "Failed one or more claims");
		return 1;
	}

	if (!sig_len) {
		if (config->key || config->alg != JWT_ALG_NONE ||
		    jwt->alg != JWT_ALG_NONE) {
			jwt_write_error(jwt,
				"Expected a signature, but JWT has none");
			return 1;
		}

		return 0;
	}

	/* Signature is known to be present from this point */
	if (jwt->alg == JWT_ALG_NONE) {
		jwt_write_error(jwt, "JWT has signature block, but no alg set");
		return 1;
	}

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
		/* It's not really possible to get here due to checks in setkey */
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Config and key alg does not match");
		return 1;
		// LCOV_EXCL_STOP
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
