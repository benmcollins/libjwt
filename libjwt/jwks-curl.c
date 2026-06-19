/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
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
#include <strings.h>
#include <curl/curl.h>

struct jwks_data {
	char *buf;
	size_t size;
	size_t alloc_size;
};

/* Maximum size we will accept for a JWKS response (1 MiB). */
#define JWKS_MAX_RESPONSE_SIZE	(1024 * 1024)

/* @rfc{7517} Cached-source defaults (issue #313): cache for 5 minutes when the
 * server gives no max-age, and refresh on a kid-miss at most once a minute. */
#define JWKS_DEFAULT_TTL	300
#define JWKS_DEFAULT_COOLDOWN	60
/* Upper bound on a cache lifetime (a server max-age or a configured TTL): caps
 * how long a key set is trusted without revalidation and guards now + age from
 * overflowing time_t. One week. */
#define JWKS_MAX_TTL		(7 * 24 * 60 * 60)

/* A fetch result: the body plus the caching metadata from the response. */
struct curl_result {
	char *body;		/* jwt_malloc'd body (or NULL)			*/
	size_t len;
	long status;		/* HTTP status code (0 for non-HTTP, e.g. file)	*/
	long max_age;		/* Cache-Control max-age seconds, or -1		*/
	char *etag;		/* jwt_malloc'd ETag value, or NULL		*/
};

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

/* Case-insensitive search for @needle within @hay[0..hlen). */
static const char *ci_find(const char *hay, size_t hlen, const char *needle)
{
	size_t nlen = strlen(needle), i;

	if (nlen == 0 || hlen < nlen)
		return NULL; // LCOV_EXCL_LINE

	for (i = 0; i + nlen <= hlen; i++)
		if (!strncasecmp(hay + i, needle, nlen))
			return hay + i;

	return NULL;
}

/* Capture "Cache-Control: max-age" and "ETag" from the response headers. */
static size_t header_cb(char *buf, size_t size, size_t nitems, void *ctx)
{
	struct curl_result *out = ctx;
	size_t len = size * nitems;

	if (len >= 14 && !strncasecmp(buf, "Cache-Control:", 14)) {
		const char *p = ci_find(buf, len, "max-age=");

		if (p != NULL)
			out->max_age = strtol(p + 8, NULL, 10);
	} else if (len >= 5 && !strncasecmp(buf, "ETag:", 5)) {
		const char *v = buf + 5;
		size_t vlen;

		while (v < buf + len && (*v == ' ' || *v == '\t'))
			v++;
		vlen = (size_t)(buf + len - v);
		while (vlen > 0 && (v[vlen - 1] == '\r' || v[vlen - 1] == '\n' ||
				    v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
			vlen--;

		if (vlen > 0) {
			char *e = jwt_malloc(vlen + 1);

			if (e != NULL) {
				memcpy(e, v, vlen);
				e[vlen] = '\0';
				jwt_freemem(out->etag);	/* last wins */
				out->etag = e;
			}
		}
	}

	return len;
}

/* Fetch @url, capturing the body and the response's caching metadata. When
 * @if_none_match is set it is sent as a conditional GET (so a 304 is possible).
 * Returns 0 on a completed request (out->status carries the HTTP code). */
static int __curl_fetch(jwk_set_t *jwk_set, const char *url, int verify,
			const char *if_none_match, struct curl_result *out)
{
	static int curl_inited;
	struct curl_slist *hdrs = NULL;
	struct jwks_data data;
	char *inm = NULL;
	CURLcode res;
	CURL *curl;

	memset(&data, 0, sizeof(data));
	memset(out, 0, sizeof(*out));
	out->max_age = -1;

	/* curl_global_init() must run once. Doing it per request and pairing it
	 * with curl_global_cleanup() tears down and rebuilds libcurl's global
	 * state on every cached fetch; init once and let it be released at exit. */
	if (!curl_inited) {
		curl_global_init(CURL_GLOBAL_DEFAULT);
		curl_inited = 1;
	}
	curl = curl_easy_init();
	if (curl == NULL)
		return 1; // LCOV_EXCL_LINE

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)out);

	/* Belt to the write_cb cap: let libcurl abort early when the server
	 * advertises an oversized body via Content-Length. */
	curl_easy_setopt(curl, CURLOPT_MAXFILESIZE,
			 (long)JWKS_MAX_RESPONSE_SIZE);

	/* Hostname verification is meaningless without peer (CA chain)
	 * verification, so tie the two together: any verify >= 1 enables full
	 * verification; only verify == 0 (explicitly insecure) disables it. */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (verify > 0) ? 2L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (verify > 0) ? 1L : 0L);

	if (if_none_match != NULL &&
	    asprintf(&inm, "If-None-Match: %s", if_none_match) > 0) {
		hdrs = curl_slist_append(NULL, inm);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	}

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out->status);

	if (hdrs != NULL)
		curl_slist_free_all(hdrs);
	free(inm);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		jwt_write_error(jwk_set, "%s", curl_easy_strerror(res));
		jwt_freemem(data.buf);
		jwt_freemem(out->etag);
		out->etag = NULL;
		return 1;
	}

	out->body = data.buf;
	out->len = data.size;

	return 0;
}

static char *__curl_get(jwk_set_t *jwk_set, const char *url, size_t *len,
			int verify)
{
	struct curl_result r;

	if (__curl_fetch(jwk_set, url, verify, NULL, &r))
		return NULL;

	jwt_freemem(r.etag);	/* the one-shot loader ignores caching headers */
	*len = r.len;

	return r.body;
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

/* @rfc{8725} Only http(s) is allowed for a cached source, to avoid an SSRF /
 * local-file-read vector (the one-shot jwks_load_fromurl still allows file://). */
static int url_scheme_ok(const char *url)
{
	return !strncasecmp(url, "http://", 7) ||
	       !strncasecmp(url, "https://", 8);
}

static char *cache_strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *d = jwt_malloc(n);

	if (d != NULL)
		memcpy(d, s, n);

	return d;
}

/* Apply a completed fetch to the cached set. Only a 2xx replaces the keys (and
 * only when the body is a usable JWKS); a 304 keeps them; any other HTTP status
 * keeps the previously cached keys and sets an error (so a transient 4xx/5xx or
 * an unfollowed redirect does not wipe a good cache). On a successful refresh
 * the ETag and expiry are updated; @last_fetch is stamped by the caller on every
 * attempt (so a failed attempt still consumes the cooldown). */
static void cache_apply(jwk_set_t *jwk_set, struct curl_result *r)
{
	struct jwks_url_cache *c = jwk_set->cache;
	time_t now = time(NULL);
	long age;

	if (r->status == 304) {
		/* Not Modified: keep the existing keys. */
	} else if (r->status >= 200 && r->status < 300) {
		/* Replace, but only if the new body is a usable JWKS; a 2xx with
		 * a garbage/empty body must not wipe a previously good cache. */
		jwk_set_t *tmp = jwks_create(r->body);
		int ok = (tmp != NULL && !jwks_error(tmp) &&
			  jwks_item_count(tmp) > 0);

		jwks_free(tmp);
		if (!ok) {
			jwt_write_error(jwk_set,
				"JWKS refresh returned no usable keys");
			return;	/* keep the previously cached keys */
		}
		jwks_item_free_all(jwk_set);
		jwks_load_strn(jwk_set, r->body, r->len);
	} else {
		/* HTTP error (e.g. 4xx/5xx, or an unfollowed 3xx): retain the
		 * previously cached keys per the documented contract. */
		jwt_write_error(jwk_set,
			"JWKS refresh failed (HTTP status %ld)", r->status);
		return;
	}

	if (r->etag != NULL) {
		jwt_freemem(c->etag);
		c->etag = r->etag;
		r->etag = NULL;
	}

	/* Clamp the (possibly server-controlled) max-age so it cannot pin the
	 * cache forever or overflow time_t in the expiry computation. */
	age = (r->max_age >= 0) ? r->max_age : c->ttl;
	if (age < 0)
		age = 0;
	if (age > JWKS_MAX_TTL)
		age = JWKS_MAX_TTL;
	c->expiry = now + age;
}

jwk_set_t *jwks_load_fromurl_cached(jwk_set_t *jwk_set, const char *url,
				    const jwks_url_config_t *config)
{
	struct jwks_url_cache *c;
	struct curl_result r;

	if (url == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_create(NULL);
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	if (!url_scheme_ok(url)) {
		jwt_write_error(jwk_set,
			"Only http(s) URLs are allowed for a cached JWKS source");
		return jwk_set;
	}

	c = jwk_set->cache;

	/* First use, or the URL changed: (re)initialize the cache and fetch. */
	if (c == NULL || c->url == NULL || strcmp(c->url, url)) {
		if (c == NULL) {
			c = jwt_malloc(sizeof(*c));
			if (c == NULL)
				return jwk_set; // LCOV_EXCL_LINE
			memset(c, 0, sizeof(*c));
			jwk_set->cache = c;
		} else {
			jwt_freemem(c->url);
			jwt_freemem(c->etag);
			c->etag = NULL;
			jwks_item_free_all(jwk_set);
		}
		c->url = cache_strdup(url);
		c->verify = config ? config->verify : 1;
		c->ttl = (config && config->ttl > 0) ? config->ttl
						     : JWKS_DEFAULT_TTL;
		c->cooldown = (config && config->cooldown >= 0) ? config->cooldown
								: JWKS_DEFAULT_COOLDOWN;

		c->last_fetch = time(NULL);
		if (__curl_fetch(jwk_set, url, c->verify, NULL, &r))
			return jwk_set;	/* error set; no keys yet */
		cache_apply(jwk_set, &r);
		jwt_freemem(r.body);
		jwt_freemem(r.etag);
		return jwk_set;
	}

	/* Fresh: serve from cache with no network request. */
	if (time(NULL) < c->expiry)
		return jwk_set;

	/* Stale: conditional GET. On failure keep the (stale) keys + set error. */
	c->last_fetch = time(NULL);
	if (__curl_fetch(jwk_set, url, c->verify, c->etag, &r))
		return jwk_set;
	cache_apply(jwk_set, &r);
	jwt_freemem(r.body);
	jwt_freemem(r.etag);

	return jwk_set;
}

jwk_set_t *jwks_refresh_fromurl(jwk_set_t *jwk_set)
{
	struct jwks_url_cache *c;
	struct curl_result r;

	if (jwk_set == NULL || jwk_set->cache == NULL ||
	    jwk_set->cache->url == NULL)
		return jwk_set;

	c = jwk_set->cache;

	/* @rfc{8725} Cooldown: bound how often a kid-miss can force an outbound
	 * fetch, so random unknown kids cannot amplify into a request flood. The
	 * attempt is stamped BEFORE the fetch so that a failing/unreachable origin
	 * still consumes the cooldown window (otherwise the throttle never
	 * engages while the endpoint is down). */
	if (time(NULL) - c->last_fetch < c->cooldown)
		return jwk_set;

	c->last_fetch = time(NULL);
	if (__curl_fetch(jwk_set, c->url, c->verify, c->etag, &r))
		return jwk_set;
	cache_apply(jwk_set, &r);
	jwt_freemem(r.body);
	jwt_freemem(r.etag);

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

jwk_set_t *jwks_load_fromurl_cached(jwk_set_t *jwk_set, const char *url,
				    const jwks_url_config_t *config)
{
	(void)jwk_set;
	(void)url;
	(void)config;
	return NULL;
}

jwk_set_t *jwks_refresh_fromurl(jwk_set_t *jwk_set)
{
	return jwk_set;
}

#endif

jwk_set_t *jwks_create_fromurl(const char *url, int verify)
{
	return jwks_load_fromurl(NULL, url, verify);
}
