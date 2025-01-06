/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
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

#define APPEND_STR(__buf, __str) do {	\
	if (__append_str(__buf, __str))	\
		return ENOMEM;		\
} while (0)

static int write_js(const json_t *js, char **buf, int pretty)
{
	/* Sort keys for repeatability */
	size_t flags = JSON_SORT_KEYS;
	char_auto *serial = NULL;

	if (pretty) {
		APPEND_STR(buf, "\n");
		flags |= JSON_INDENT(4);
	} else {
		flags |= JSON_COMPACT;
	}

	serial = json_dumps(js, flags);

	APPEND_STR(buf, serial);

	if (pretty)
		APPEND_STR(buf, "\n");

	return 0;
}

static int jwt_write_head(jwt_t *jwt, char **buf, int pretty)
{
	int ret = 0;

	if (jwt->alg != JWT_ALG_NONE) {
		/* Only add default 'typ' header if it has not been defined,
		 * allowing for any value of it. This allows for signaling
		 * of application specific extensions to JWT, such as PASSporT,
		 * RFC 8225. */
		if ((ret = jwt_add_header(jwt, "typ", "JWT"))) {
			if (ret != EEXIST)
				return ret;
		}
	}

	if ((ret = jwt_del_headers(jwt, "alg")))
		return ret;

	if ((ret = jwt_add_header(jwt, "alg", jwt_alg_str(jwt->alg))))
		return ret;

	return write_js(jwt->headers, buf, pretty);
}

static int jwt_write_body(jwt_t *jwt, char **buf, int pretty)
{
	return write_js(jwt->grants, buf, pretty);
}

static int jwt_dump(jwt_t *jwt, char **buf, int pretty)
{
	int ret;

	ret = jwt_write_head(jwt, buf, pretty);

	if (ret == 0)
		ret = __append_str(buf, ".");

	if (ret == 0)
		ret = jwt_write_body(jwt, buf, pretty);

	return ret;
}

char *jwt_dump_grants_str(jwt_t *jwt, int pretty)
{
	char *out = NULL;

	errno = jwt_write_body(jwt, &out, pretty);

	if (errno)
		jwt_freemem(out);

	return out;
}

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	char_auto *out = NULL;
	int ret = 0;

	ret = jwt_dump(jwt, &out, pretty);

	if (ret == 0)
		fputs(out, fp);

	return ret;
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
	char *out = NULL;

	errno = jwt_dump(jwt, &out, pretty);

	if (errno)
		jwt_freemem(out);

	return out;
}

static int jwt_encode(jwt_t *jwt, char **out)
{
	char_auto *head = NULL, *body = NULL, *sig = NULL;
	char *buf = NULL;
	int ret, head_len, body_len;
	unsigned int sig_len;

	if (out == NULL)
		return EINVAL;
	*out = NULL;

	/* First the header. */
	ret = jwt_write_head(jwt, &buf, 0);
	if (ret)
		return ret;
	/* Encode it */
	head_len = jwt_base64uri_encode(&head, buf, (int)strlen(buf));
	jwt_freemem(buf);

	if (head_len <= 0)
		return -head_len;

	/* Now the body. */
	ret = jwt_write_body(jwt, &buf, 0);
	if (ret)
		return ret;

	body_len = jwt_base64uri_encode(&body, buf, (int)strlen(buf));
	jwt_freemem(buf);

	if (body_len <= 0)
		return -body_len;

	/* The part we need to sign, but add space for 2 dots and a nil */
	buf = jwt_malloc(head_len + body_len + 3);
	if (buf == NULL)
		return ENOMEM;

	strcpy(buf, head);
	strcat(buf, ".");
	strcat(buf, body);

	if (jwt->alg == JWT_ALG_NONE) {
		/* Add the trailing dot, and send it back */
		strcat(buf, ".");
		*out = buf;
		return 0;
	}

	/* At this point buf has "head.body" */

	/* Now the signature. */
	ret = jwt_sign(jwt, &sig, &sig_len, buf, strlen(buf));
	jwt_freemem(buf);
	if (ret)
		return ret;

	ret = jwt_base64uri_encode(&buf, sig, sig_len);
	/* At this point buf has b64 of sig and ret is size of it */

	if (ret < 0)
		return ENOMEM;

	/* plus 2 dots and a nil */
	ret = strlen(head) + strlen(body) + strlen(buf) + 3;

	/* We're good, so let's get it all together */
	*out = jwt_malloc(ret);
	if (*out == NULL) {
		ret = ENOMEM;
	} else {
		sprintf(*out, "%s.%s.%s", head, body, buf);
		ret = 0;
	}

	jwt_freemem(buf);

	return ret;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	char_auto *str = NULL;

	errno = jwt_encode(jwt, &str);
	if (!errno)
		fputs(str, fp);

	return errno;
}

char *jwt_encode_str(jwt_t *jwt)
{
	char *str = NULL;

	errno = jwt_encode(jwt, &str);
	if (errno)
		jwt_freemem(str);

	return str;
}
