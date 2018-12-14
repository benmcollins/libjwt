/* Copyright (C) 2015-2018 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <jwt.h>

#include "jwt-private.h"
#include "base64.h"
#include "config.h"


const char *jwt_alg_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	case JWT_ALG_HS384:
		return "HS384";
	case JWT_ALG_HS512:
		return "HS512";
	case JWT_ALG_RS256:
		return "RS256";
	case JWT_ALG_RS384:
		return "RS384";
	case JWT_ALG_RS512:
		return "RS512";
	case JWT_ALG_ES256:
		return "ES256";
	case JWT_ALG_ES384:
		return "ES384";
	case JWT_ALG_ES512:
		return "ES512";
	default:
		return NULL;
	}
}

jwt_alg_t jwt_str_alg(const char *alg)
{
	if (alg == NULL)
		return JWT_ALG_INVAL;

	if (!strcasecmp(alg, "none"))
		return JWT_ALG_NONE;
	else if (!strcasecmp(alg, "HS256"))
		return JWT_ALG_HS256;
	else if (!strcasecmp(alg, "HS384"))
		return JWT_ALG_HS384;
	else if (!strcasecmp(alg, "HS512"))
		return JWT_ALG_HS512;
	else if (!strcasecmp(alg, "RS256"))
		return JWT_ALG_RS256;
	else if (!strcasecmp(alg, "RS384"))
		return JWT_ALG_RS384;
	else if (!strcasecmp(alg, "RS512"))
		return JWT_ALG_RS512;
	else if (!strcasecmp(alg, "ES256"))
		return JWT_ALG_ES256;
	else if (!strcasecmp(alg, "ES384"))
		return JWT_ALG_ES384;
	else if (!strcasecmp(alg, "ES512"))
		return JWT_ALG_ES512;

	return JWT_ALG_INVAL;
}

static void jwt_scrub_key(jwt_t *jwt)
{
	if (jwt->key) {
		/* Overwrite it so it's gone from memory. */
		memset(jwt->key, 0, jwt->key_len);

		free(jwt->key);
		jwt->key = NULL;
	}

	jwt->key_len = 0;
	jwt->alg = JWT_ALG_NONE;
}

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, const unsigned char *key, int len)
{
	/* No matter what happens here, we do this. */
	jwt_scrub_key(jwt);

	if (alg < JWT_ALG_NONE || alg >= JWT_ALG_INVAL)
		return EINVAL;

	switch (alg) {
	case JWT_ALG_NONE:
		if (key || len)
			return EINVAL;
		break;

	default:
		if (!key || len <= 0)
			return EINVAL;

		jwt->key = malloc(len);
		if (!jwt->key)
			return ENOMEM;

		memcpy(jwt->key, key, len);
	}

	jwt->alg = alg;
	jwt->key_len = len;

	return 0;
}

jwt_alg_t jwt_get_alg(jwt_t *jwt)
{
	return jwt->alg;
}

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = malloc(sizeof(jwt_t));
	if (!*jwt)
		return ENOMEM;

	memset(*jwt, 0, sizeof(jwt_t));

	(*jwt)->grants = json_object();
	if (!(*jwt)->grants) {
		free(*jwt);
		*jwt = NULL;
		return ENOMEM;
	}

	(*jwt)->headers = json_object();
	if (!(*jwt)->headers) {
		json_decref((*jwt)->grants);
		free(*jwt);
		*jwt = NULL;
		return ENOMEM;
	}

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	jwt_scrub_key(jwt);

	json_decref(jwt->grants);
	json_decref(jwt->headers);

	free(jwt);
}

jwt_t *jwt_dup(jwt_t *jwt)
{
	jwt_t *new = NULL;

	if (!jwt) {
		errno = EINVAL;
		goto dup_fail;
	}

	errno = 0;

	new = malloc(sizeof(jwt_t));
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}

	memset(new, 0, sizeof(jwt_t));

	if (jwt->key_len) {
		new->alg = jwt->alg;
		new->key = malloc(jwt->key_len);
		if (!new->key) {
			errno = ENOMEM;
			goto dup_fail;
		}
		memcpy(new->key, jwt->key, jwt->key_len);
		new->key_len = jwt->key_len;
	}

	new->grants = json_deep_copy(jwt->grants);
	if (!new->grants)
		errno = ENOMEM;

	new->headers = json_deep_copy(jwt->headers);
	if (!new->headers)
		errno = ENOMEM;

dup_fail:
	if (errno) {
		jwt_free(new);
		new = NULL;
	}

	return new;
}

static const char *get_js_string(json_t *js, const char *key)
{
	const char *val = NULL;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		val = json_string_value(js_val);
	} else {
		errno = ENOENT;
	}

	return val;
}

static long get_js_int(json_t *js, const char *key)
{
	long val = -1;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		val = (long)json_integer_value(js_val);
	} else {
		errno = ENOENT;
	}

	return val;
}

static int get_js_bool(json_t *js, const char *key)
{
	int val = -1;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val) {
		val = (int)json_is_true(js_val);
	} else {
		errno = ENOENT;
	}
	return val;
}

void *jwt_b64_decode(const char *src, int *ret_len)
{
	void *buf;
	char *new;
	int len, i, z;

	/* Decode based on RFC-4648 URI safe encoding. */
	len = strlen(src);
	new = alloca(len + 4);
	if (!new)
		return NULL;

	for (i = 0; i < len; i++) {
		switch (src[i]) {
		case '-':
			new[i] = '+';
			break;
		case '_':
			new[i] = '/';
			break;
		default:
			new[i] = src[i];
		}
	}
	z = 4 - (i % 4);
	if (z < 4) {
		while (z--)
			new[i++] = '=';
	}
	new[i] = '\0';

	buf = malloc(i);
	if (buf == NULL)
		return NULL;

	*ret_len = jwt_Base64decode(buf, new);

	return buf;
}


static json_t *jwt_b64_decode_json(char *src)
{
	json_t *js;
	char *buf;
	int len;

	buf = jwt_b64_decode(src, &len);

	if (buf == NULL)
		return NULL;

	buf[len] = '\0';

	js = json_loads(buf, 0, NULL);

	free(buf);

	return js;
}

void jwt_base64uri_encode(char *str)
{
	int len = strlen(str);
	int i, t;

	for (i = t = 0; i < len; i++) {
		switch (str[i]) {
		case '+':
			str[t++] = '-';
			break;
		case '/':
			str[t++] = '_';
			break;
		case '=':
			break;
		default:
			str[t++] = str[i];
		}
	}

	str[t] = '\0';
}

static int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return jwt_sign_sha_hmac(jwt, out, len, str);

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		return jwt_sign_sha_pem(jwt, out, len, str);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

static int jwt_verify(jwt_t *jwt, const char *head, const char *sig)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return jwt_verify_sha_hmac(jwt, head, sig);

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		return jwt_verify_sha_pem(jwt, head, sig);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

static int jwt_parse_body(jwt_t *jwt, char *body)
{
	if (jwt->grants) {
		json_decref(jwt->grants);
		jwt->grants = NULL;
	}

	jwt->grants = jwt_b64_decode_json(body);
	if (!jwt->grants)
		return EINVAL;

	return 0;
}

static int jwt_parse_head(jwt_t *jwt, char *head)
{
	if (jwt->headers) {
		json_decref(jwt->headers);
		jwt->headers = NULL;
	}

	jwt->headers = jwt_b64_decode_json(head);
	if (!jwt->headers)
		return EINVAL;

	return 0;
}

static int jwt_verify_head(jwt_t *jwt, char *head)
{
	int ret = 0;
	if ((ret = jwt_parse_head(jwt, head))) {
		return ret;
	}

	const char *val;

	val = get_js_string(jwt->headers, "alg");
	jwt->alg = jwt_str_alg(val);
	if (jwt->alg == JWT_ALG_INVAL) {
		ret = EINVAL;
		goto verify_head_done;
	}

	if (jwt->alg != JWT_ALG_NONE) {
		/* If alg is not NONE, there may be a typ. */
		val = get_js_string(jwt->headers, "typ");
		if (val && strcasecmp(val, "JWT"))
			ret = EINVAL;

		if (jwt->key) {
			if (jwt->key_len <= 0)
				ret = EINVAL;
		} else {
			jwt_scrub_key(jwt);
		}
	} else {
		/* If alg is NONE, there should not be a key */
		if (jwt->key){
			ret = EINVAL;
		}
	}

verify_head_done:

	return ret;
}

int jwt_decode(jwt_t **jwt, const char *token, const unsigned char *key,
	       int key_len)
{
	char *head = strdup(token);
	jwt_t *new = NULL;
	char *body, *sig;
	int ret = EINVAL;

	if (!jwt)
		return EINVAL;

	*jwt = NULL;

	if (!head)
		return ENOMEM;

	/* Find the components. */
	for (body = head; body[0] != '.'; body++) {
		if (body[0] == '\0')
			goto decode_done;
	}

	body[0] = '\0';
	body++;

	for (sig = body; sig[0] != '.'; sig++) {
		if (sig[0] == '\0')
			goto decode_done;
	}

	sig[0] = '\0';
	sig++;

	/* Now that we have everything split up, let's check out the
	 * header. */
	ret = jwt_new(&new);
	if (ret) {
		goto decode_done;
	}

	/* Copy the key over for verify_head. */
	if (key_len) {
		new->key = malloc(key_len);
		if (new->key == NULL)
			goto decode_done;
		memcpy(new->key, key, key_len);
		new->key_len = key_len;
	}

	ret = jwt_verify_head(new, head);
	if (ret)
		goto decode_done;

	ret = jwt_parse_body(new, body);
	if (ret)
		goto decode_done;

	/* Check the signature, if needed. */
	if (new->alg != JWT_ALG_NONE) {
		/* Re-add this since it's part of the verified data. */
		body[-1] = '.';
		ret = jwt_verify(new, head, sig);
	} else {
		ret = 0;
	}

decode_done:
	if (ret)
		jwt_free(new);
	else
		*jwt = new;

	free(head);

	return ret;
}

const char *jwt_get_grant(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->grants, grant);
}

long jwt_get_grant_int(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->grants, grant);
}

int jwt_get_grant_bool(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_bool(jwt->grants, grant);
}

char *jwt_get_grants_json(jwt_t *jwt, const char *grant)
{
	json_t *js_val = NULL;

	errno = EINVAL;

	if (!jwt)
		return NULL;

	if (grant && strlen(grant))
		js_val = json_object_get(jwt->grants, grant);
	else
		js_val = jwt->grants;

	if (js_val == NULL)
		return NULL;

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	if (!jwt || !grant || !strlen(grant) || !val)
		return EINVAL;

	if (get_js_string(jwt->grants, grant) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_add_grant_int(jwt_t *jwt, const char *grant, long val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt->grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_add_grant_bool(jwt_t *jwt, const char *grant, int val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt->grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_boolean(val)))
		return EINVAL;

	return 0;
}

int jwt_add_grants_json(jwt_t *jwt, const char *json)
{
	json_t *js_val;
	int ret = -1;

	if (!jwt)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt->grants, js_val);

	json_decref(js_val);

	return ret ? EINVAL : 0;
}

int jwt_del_grants(jwt_t *jwt, const char *grant)
{
	if (!jwt)
		return EINVAL;

	if (grant == NULL || !strlen(grant))
		json_object_clear(jwt->grants);
	else
		json_object_del(jwt->grants, grant);

	return 0;
}

#ifdef _MSC_VER

int jwt_del_grant(jwt_t *jwt, const char *grant);
#pragma comment(linker, "/alternatename:jwt_del_grant=jwt_del_grants")

#else

#ifdef NO_WEAK_ALIASES
int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	return jwt_del_grants(jwt, grant);
}
#else
int jwt_del_grant(jwt_t *jwt, const char *grant)
	__attribute__ ((weak, alias ("jwt_del_grants")));
#endif

#endif /* _MSC_VER */

const char *jwt_get_header(jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->headers, header);
}

long jwt_get_header_int(jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->headers, header);
}

int jwt_get_header_bool(jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_bool(jwt->headers, header);
}

char *jwt_get_headers_json(jwt_t *jwt, const char *header)
{
	json_t *js_val = NULL;

	errno = EINVAL;

	if (!jwt)
		return NULL;

	if (header && strlen(header))
		js_val = json_object_get(jwt->headers, header);
	else
		js_val = jwt->headers;

	if (js_val == NULL)
		return NULL;

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

int jwt_add_header(jwt_t *jwt, const char *header, const char *val)
{
	if (!jwt || !header || !strlen(header) || !val)
		return EINVAL;

	if (get_js_string(jwt->headers, header) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_add_header_int(jwt_t *jwt, const char *header, long val)
{
	if (!jwt || !header || !strlen(header))
		return EINVAL;

	if (get_js_int(jwt->headers, header) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_add_header_bool(jwt_t *jwt, const char *header, int val)
{
	if (!jwt || !header || !strlen(header))
		return EINVAL;

	if (get_js_int(jwt->headers, header) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_boolean(val)))
		return EINVAL;

	return 0;
}

int jwt_add_headers_json(jwt_t *jwt, const char *json)
{
	json_t *js_val;
	int ret = -1;

	if (!jwt)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt->headers, js_val);

	json_decref(js_val);

	return ret ? EINVAL : 0;
}

int jwt_del_headers(jwt_t *jwt, const char *header)
{
	if (!jwt)
		return EINVAL;

	if (header == NULL || !strlen(header))
		json_object_clear(jwt->headers);
	else
		json_object_del(jwt->headers, header);

	return 0;
}

static int __append_str(char **buf, const char *str)
{
	char *new;

	if (*buf == NULL) {
		new = calloc(1, strlen(str) + 1);
	} else {
		new = realloc(*buf, strlen(*buf) + strlen(str) + 1);
	}

	if (new == NULL)
		return ENOMEM;

	strcat(new, str);

	*buf = new;

	return 0;
}

#define APPEND_STR(__buf, __str) do {		\
	int ret = __append_str(__buf, __str);	\
	if (ret)				\
		return ret;			\
} while(0)

static int write_js(const json_t *js, char **buf, int pretty)
{
	/* Sort keys for repeatability */
	size_t flags = JSON_SORT_KEYS;
	char *serial;

	if (pretty) {
		APPEND_STR(buf, "\n");
		flags |= JSON_INDENT(4);
	} else {
		flags |= JSON_COMPACT;
	}

	serial = json_dumps(js, flags);

	APPEND_STR(buf, serial);

	free(serial);

	if (pretty)
		APPEND_STR(buf, "\n");

	return 0;
}

static int jwt_write_head(jwt_t *jwt, char **buf, int pretty)
{
	int ret = 0;

	if (jwt->alg != JWT_ALG_NONE) {
		if ((ret = jwt_del_headers(jwt, "typ")))
			return ret;

		if ((ret = jwt_add_header(jwt, "typ", "JWT")))
			return ret;
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

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	char *out = NULL;
	int ret = 0;

	ret = jwt_dump(jwt, &out, pretty);

	if (ret == 0)
		fputs(out, fp);

	if (out)
		free(out);

	return ret;
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
	char *out = NULL;
	int err;

	err = jwt_dump(jwt, &out, pretty);

	if (err) {
		errno = err;
		if (out)
			free(out);
		out = NULL;
	} else {
		errno = 0;
	}

	return out;
}

static int jwt_encode(jwt_t *jwt, char **out)
{
	char *buf = NULL, *head, *body, *sig;
	int ret, head_len, body_len;
	unsigned int sig_len;

	/* First the header. */
	ret = jwt_write_head(jwt, &buf, 0);
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	head = alloca(strlen(buf) * 2);
	if (head == NULL) {
		free(buf);
		return ENOMEM;
	}
	jwt_Base64encode(head, buf, strlen(buf));
	head_len = strlen(head);

	free(buf);
	buf = NULL;

	/* Now the body. */
	ret = jwt_write_body(jwt, &buf, 0);
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	body = alloca(strlen(buf) * 2);
	if (body == NULL) {
		free(buf);
		return ENOMEM;
	}
	jwt_Base64encode(body, buf, strlen(buf));
	body_len = strlen(body);

	free(buf);
	buf = NULL;

	jwt_base64uri_encode(head);
	jwt_base64uri_encode(body);

	/* Allocate enough to reuse as b64 buffer. */
	buf = malloc(head_len + body_len + 2);
	if (buf == NULL)
		return ENOMEM;
	strcpy(buf, head);
	strcat(buf, ".");
	strcat(buf, body);

	ret = __append_str(out, buf);
	if (ret == 0)
		ret = __append_str(out, ".");
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	if (jwt->alg == JWT_ALG_NONE) {
		free(buf);
		return 0;
	}

	/* Now the signature. */
	ret = jwt_sign(jwt, &sig, &sig_len, buf);
	free(buf);

	if (ret)
		return ret;

	buf = malloc(sig_len * 2);
	if (buf == NULL) {
		free(sig);
		return ENOMEM;
	}

	jwt_Base64encode(buf, sig, sig_len);

	free(sig);

	jwt_base64uri_encode(buf);
	ret = __append_str(out, buf);
	free(buf);

	return ret;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	char *str = NULL;
	int ret;

	ret = jwt_encode(jwt, &str);
	if (ret) {
		if (str)
			free(str);
		return ret;
	}

	fputs(str, fp);
	free(str);

	return 0;
}

char *jwt_encode_str(jwt_t *jwt)
{
	char *str = NULL;

	errno = jwt_encode(jwt, &str);
	if (errno) {
		if (str)
			free(str);
		str = NULL;
	}

	return str;
}
