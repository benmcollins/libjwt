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

#include "base64.h"

#include "jwt-private.h"

static int write_js(const json_t *js, char **buf)
{
	*buf = json_dumps(js, JSON_SORT_KEYS | JSON_COMPACT);

	return *buf == NULL ? 1 : 0;
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
