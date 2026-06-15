/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>
#include "jwt-private.h"

#ifdef HAVE_LIBCURL
#include <curl/curl.h>

struct jwks_data {
	char *buf;
	size_t size;
	size_t alloc_size;
};

/* Maximum size we will accept for a JWKS response (1 MiB). */
#define JWKS_MAX_RESPONSE_SIZE	(1024 * 1024)

/* Grow the response buffer to hold at least need bytes plus a NUL. The caller
 * has already bounded need by JWKS_MAX_RESPONSE_SIZE, so need + 1 cannot
 * overflow. Returns 0 on success. */
static int jwks_buf_reserve(struct jwks_data *data, size_t need)
{
	size_t new_alloc;
	char *tmp;

	if (need + 1 <= data->alloc_size)
		return 0; // LCOV_EXCL_LINE

	/* Grow geometrically, capped at the maximum response size (+1 NUL). */
	new_alloc = data->alloc_size ? data->alloc_size : 4096;
	while (new_alloc < need + 1)
		new_alloc *= 2;
	if (new_alloc > JWKS_MAX_RESPONSE_SIZE + 1)
		new_alloc = JWKS_MAX_RESPONSE_SIZE + 1;

	/* Use the jwt allocator (no jwt_realloc exists) so a custom
	 * jwt_set_alloc() applies and the caller's jwt_freemem() matches. */
	tmp = jwt_malloc(new_alloc);
	if (tmp == NULL)
		return 1; // LCOV_EXCL_LINE

	if (data->size)
		memcpy(tmp, data->buf, data->size);
	jwt_freemem(data->buf);

	data->buf = tmp;
	data->alloc_size = new_alloc;

	return 0;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *ctx)
{
	size_t total_size = size * nmemb;
	struct jwks_data *data = ctx;

	if (total_size == 0)
		return 0; // LCOV_EXCL_LINE

	/* Enforce the response-size cap up front; this also keeps the
	 * data->size + total_size arithmetic below from overflowing. This is a
	 * belt behind CURLOPT_MAXFILESIZE (which catches a server-advertised
	 * oversize body first); it still bounds a body that exceeds the cap
	 * without advertising its size, e.g. chunked transfer-encoding. */
	if (total_size > JWKS_MAX_RESPONSE_SIZE ||
	    data->size > JWKS_MAX_RESPONSE_SIZE - total_size)
		return 0; // LCOV_EXCL_LINE

	/* Grow the buffer as the body streams in. This does not depend on a
	 * Content-Length header (so chunked transfer-encoding works), and a
	 * single growing buffer avoids the duplicate-header allocation leak. */
	if (jwks_buf_reserve(data, data->size + total_size))
		return 0; // LCOV_EXCL_LINE

	memcpy(&(data->buf[data->size]), contents, total_size);
	data->size += total_size;
	data->buf[data->size] = '\0';

	return total_size;
}

static char *__curl_get(jwk_set_t *jwk_set, const char *url, size_t *len,
			int verify)
{
	CURL *curl;
	CURLcode res;
	struct jwks_data data;

	memset(&data, 0, sizeof(data));
 
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl == NULL) {
		// LCOV_EXCL_START
		curl_global_cleanup();
		return NULL;
		// LCOV_EXCL_STOP
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	/* Belt to the write_cb cap: let libcurl abort early when the server
	 * advertises an oversized body via Content-Length. */
	curl_easy_setopt(curl, CURLOPT_MAXFILESIZE,
			 (long)JWKS_MAX_RESPONSE_SIZE);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (verify > 0) ? 2L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (verify > 1) ? 1L : 0L);

        res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		jwt_write_error(jwk_set, "%s", curl_easy_strerror(res));
		jwt_freemem(data.buf);
		return NULL;
	}

	*len = data.size;

	return data.buf;
}

jwk_set_t *jwks_load_fromurl(jwk_set_t *jwk_set, const char *url, int verify)
{
	char *str = NULL;
	size_t len;

	if (url == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_create(NULL);
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	str = __curl_get(jwk_set, url, &len, verify);
	if (str != NULL) {
		jwk_set = jwks_load_strn(jwk_set, str, len);
		jwt_freemem(str);
	}

	return jwk_set;
}

#else

jwk_set_t *jwks_load_fromurl(jwk_set_t *jwk_set, const char *url, int verify)
{
	(void)jwk_set;
	(void)url;
	(void)verify;
	return NULL;
}

#endif

jwk_set_t *jwks_create_fromurl(const char *url, int verify)
{
	return jwks_load_fromurl(NULL, url, verify);
}
