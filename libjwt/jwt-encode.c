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

static int write_js(const jwt_json_t *js, char **buf)
{
	*buf = jwt_json_serialize(js, JWT_JSON_SORT_KEYS | JWT_JSON_COMPACT);

	return *buf == NULL ? 1 : 0;
}

/* @rfc{7515,4.1.11} Header Parameter names defined by RFC 7515 (the JWS
 * Protected Header) and JWA (RFC 7518). A producer MUST NOT list any of
 * these in the "crit" header. The JWA names are JWE-related and not yet
 * used by LibJWT, but are banned here for forward compatibility. */
static const char * const jwt_registered_headers[] = {
	/* RFC 7515 4.1 */
	"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256",
	"typ", "cty", "crit",
	/* RFC 7518 (JWA) */
	"enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
};

static int jwt_crit_is_registered(const char *name)
{
	size_t j;

	for (j = 0; j < ARRAY_SIZE(jwt_registered_headers); j++) {
		if (!strcmp(jwt_registered_headers[j], name))
			return 1;
	}

	return 0;
}

/* @rfc{7515,4.1.11} Validate the "crit" value now present in the header,
 * regardless of how it got there (jwt_builder_setcrit() or set directly by
 * the application). It must be a non-empty array of unique strings, each
 * naming a header parameter that is present in the header and is not a
 * Header Parameter name defined by RFC 7515 or JWA. */
static int jwt_validate_crit(jwt_t *jwt, jwt_json_t *crit)
{
	jwt_json_t *ent;
	size_t i;

	if (!jwt_json_is_array(crit)) {
		jwt_write_error(jwt, "\"crit\" header must be an array");
		return 1;
	}

	if (jwt_json_arr_size(crit) == 0) {
		jwt_write_error(jwt, "\"crit\" header must not be empty");
		return 1;
	}

	jwt_json_arr_foreach(crit, i, ent) {
		const char *name;
		size_t k;

		if (!jwt_json_is_string(ent)) {
			jwt_write_error(jwt,
				"\"crit\" header entries must be strings");
			return 1;
		}

		name = jwt_json_str_val(ent);

		if (jwt_crit_is_registered(name)) {
			jwt_write_error(jwt,
				"\"crit\" cannot list registered header \"%s\"",
				name);
			return 1;
		}

		if (jwt_json_obj_get(jwt->headers, name) == NULL) {
			jwt_write_error(jwt,
				"\"crit\" lists \"%s\" which is not in the header",
				name);
			return 1;
		}

		/* Names must not be duplicated. */
		for (k = 0; k < i; k++) {
			jwt_json_t *prev = jwt_json_arr_get(crit, k);

			if (!strcmp(jwt_json_str_val(prev), name)) {
				jwt_write_error(jwt,
					"\"crit\" lists \"%s\" more than once",
					name);
				return 1;
			}
		}
	}

	return 0;
}

/* @rfc{7515,4.1.11} Emit and/or validate the "crit" (Critical) header.
 *
 * @crit is a NULL-terminated list of header parameter names the producer
 * registered via jwt_builder_setcrit(); it may be NULL. Any registered name
 * is appended to the header's "crit" array (created if needed). Regardless
 * of whether anything was registered, if the header ends up with a "crit"
 * value (e.g. the application set one directly) it is fully validated so a
 * non-conforming "crit" is never emitted.
 */
int jwt_write_crit(jwt_t *jwt, char * const *crit)
{
	jwt_json_t *arr;
	size_t i;

	arr = jwt_json_obj_get(jwt->headers, "crit");

	/* If the producer registered names, fold them into the header's
	 * "crit" array (creating it if the application didn't set one). */
	if (crit && crit[0]) {
		if (arr == NULL) {
			arr = jwt_json_create_arr();
			if (arr == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error allocating \"crit\" array");
				return 1;
				// LCOV_EXCL_STOP
			}
			/* obj_set steals the reference to arr (on success and,
			 * per the backend contract, on failure too — so we do
			 * not release it here, matching the rest of LibJWT). */
			if (jwt_json_obj_set(jwt->headers, "crit", arr)) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error setting \"crit\" in header");
				return 1;
				// LCOV_EXCL_STOP
			}
		} else if (!jwt_json_is_array(arr)) {
			/* App set a non-array "crit"; can't append to it.
			 * Let validation below report the error. */
			return jwt_validate_crit(jwt, arr);
		}

		for (i = 0; crit[i] != NULL; i++) {
			jwt_json_t *str = jwt_json_create_str(crit[i]);

			if (str == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error allocating \"crit\" entry");
				return 1;
				// LCOV_EXCL_STOP
			}

			/* Append steals the reference to str. */
			jwt_json_arr_append(arr, str);
		}
	}

	/* Nothing registered and the app set no "crit": nothing to do. */
	if (arr == NULL)
		return 0;

	return jwt_validate_crit(jwt, arr);
}

int jwt_head_setup(jwt_t *jwt)
{
	jwt_value_t jval;

	if (jwt->alg != JWT_ALG_NONE) {

		/* Only set default 'typ' header if it has not been defined,
		 * allowing for any value of it. This allows for signaling
		 * of application specific extensions to JWT, such as PASSporT,
		 * RFC 8225. */
		jwt_set_SET_STR(&jval, "typ", "JWT");
		if (jwt_header_set(jwt, &jval)) {
			if (jval.error != JWT_VALUE_ERR_EXIST) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error setting \"typ\" in header");
				return 1;
				// LCOV_EXCL_STOP
			}
		}
	}

	jwt_set_SET_STR(&jval, "alg", jwt_alg_str(jwt->alg));
	jval.replace = 1;
	if (jwt_header_set(jwt, &jval)) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error setting \"alg\" in header");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

static int jwt_encode(jwt_t *jwt, char **out)
{
	char_auto *head = NULL, *payload = NULL, *sig = NULL;
	char *buf = NULL;
	int ret, head_len, payload_len;
	unsigned int sig_len;

	if (out == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "No string passed to write out to");
		return 1;
		// LCOV_EXCL_STOP
	}
	*out = NULL;

	/* First the header. */
	ret = write_js(jwt->headers, &buf);
	if (ret)
		return 1; // LCOV_EXCL_LINE
	/* Encode it */
	head_len = jwt_base64uri_encode(&head, buf, (int)strlen(buf));
	jwt_freemem(buf);

	if (head_len <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error encoding header");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* Now the payload. */
	ret = write_js(jwt->claims, &buf);
	if (ret) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error writing payload");
		return 1;
		// LCOV_EXCL_STOP
	}

	payload_len = jwt_base64uri_encode(&payload, buf, (int)strlen(buf));
	jwt_freemem(buf);

	if (payload_len <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error encoding payload");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* The part we need to sign, but add space for 2 dots and a nil */
	buf = jwt_malloc(head_len + payload_len + 3);
	if (buf == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	strcpy(buf, head);
	strcat(buf, ".");
	strcat(buf, payload);

	if (jwt->alg == JWT_ALG_NONE) {
		/* Add the trailing dot, and send it back */
		strcat(buf, ".");
		*out = buf;
		return 0;
	}

	/* At this point buf has "head.payload" */

	/* Now the signature. */
	ret = jwt_sign(jwt, &sig, &sig_len, buf, strlen(buf));
	jwt_freemem(buf);
	if (ret) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return ret;
		// LCOV_EXCL_STOP
	}

	ret = jwt_base64uri_encode(&buf, sig, sig_len);
	/* At this point buf has b64 of sig and ret is size of it */

	if (ret < 0) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* plus 2 dots and a nil */
	ret = strlen(head) + strlen(payload) + strlen(buf) + 3;

	/* We're good, so let's get it all together */
	*out = jwt_malloc(ret);
	// LCOV_EXCL_START
	if (*out == NULL) {
		jwt_write_error(jwt, "Error allocating memory");
		ret = 1;
	} else {
		sprintf(*out, "%s.%s.%s", head, payload, buf);
		ret = 0;
	}
	// LCOV_EXCL_STOP

	jwt_freemem(buf);

	return ret;
}

char *jwt_encode_str(jwt_t *jwt)
{
	char *str = NULL;

	if (jwt_encode(jwt, &str))
		jwt_freemem(str);

	return str;
}
