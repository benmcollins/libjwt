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

static size_t header_cb(char *buf, size_t size, size_t nmemb, void *ctx)
{
	size_t total_size = size * nmemb;
	struct jwks_data *data = ctx;

	if (strncmp(buf, "Content-Length:", 15))
		return total_size;

	data->alloc_size = (size_t)atol(buf + 15);
	data->buf = jwt_malloc(data->alloc_size + 1);
	if (!data->buf)
		return 0; // LCOV_EXCL_LINE

	data->size = 0;
	data->buf[0] = '\0';

	return total_size;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *ctx)
{
	size_t total_size = size * nmemb;
	struct jwks_data *data = ctx;

	if (data->size + total_size > data->alloc_size)
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
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (verify > 0) ? 2L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (verify > 1) ? 1L : 0L);

        res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		jwt_write_error(jwk_set, "%s", curl_easy_strerror(res));
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
