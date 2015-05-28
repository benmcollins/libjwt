/* Copyright (C) 2015 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include <jansson.h>

#include <jwt.h>

#include "config.h"

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
};

static const char *jwt_alg_str(jwt_alg_t alg)
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
	}

	return NULL; // LCOV_EXCL_LINE
}

static int jwt_str_alg(jwt_t *jwt, const char *alg)
{
	if (!strcasecmp(alg, "none"))
		jwt->alg = JWT_ALG_NONE;
	else if (!strcasecmp(alg, "HS256"))
		jwt->alg = JWT_ALG_HS256;
	else if (!strcasecmp(alg, "HS384"))
		jwt->alg = JWT_ALG_HS384;
	else if (!strcasecmp(alg, "HS512"))
		jwt->alg = JWT_ALG_HS512;
	else
		return EINVAL;

	return 0;
}

static int jwt_alg_key_len(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return 0;
	case JWT_ALG_HS256:
		return 32;
	case JWT_ALG_HS384:
		return 48;
	case JWT_ALG_HS512:
		return 64;
	}

	return -1; // LCOV_EXCL_LINE
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

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, unsigned char *key, int len)
{
	int key_len = jwt_alg_key_len(alg);

	/* No matter what happens here, we do this. */
	jwt_scrub_key(jwt);

	switch (alg) {
	case JWT_ALG_NONE:
		if (key || len)
			return EINVAL;
		break;

	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		if (!key || len != key_len)
			return EINVAL;

		jwt->key = malloc(key_len);
		if (!jwt->key) {
			return ENOMEM; // LCOV_EXCL_LINE
		}

		memcpy(jwt->key, key, key_len);
		break;

	default:
		return EINVAL;
	}

	jwt->alg = alg;
	jwt->key_len = key_len;

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
		return ENOMEM; // LCOV_EXCL_LINE

	memset(*jwt, 0, sizeof(jwt_t));

	(*jwt)->grants = json_object();
	if (!(*jwt)->grants) {
		// LCOV_EXCL_START
		free(*jwt);
		*jwt = NULL;
		return ENOMEM;
		// LCOV_EXCL_STOP
	}

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	jwt_scrub_key(jwt);

	json_decref(jwt->grants);

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
		// LCOV_EXCL_START
		errno = ENOMEM;
		return NULL;
		// LCOV_EXCL_STOP
	}

	memset(new, 0, sizeof(jwt_t));

	if (jwt->key_len) {
		new->key = malloc(jwt->key_len);
		if (!new->key) {
			// LCOV_EXCL_START
			errno = ENOMEM;
			goto dup_fail;
			// LCOV_EXCL_STOP
		}
		memcpy(new->key, jwt->key, jwt->key_len);
		new->key_len = jwt->key_len;
	}

	new->grants = json_deep_copy(jwt->grants);
	if (!new->grants) {
		errno = ENOMEM; // LCOV_EXCL_LINE
	} else {
		errno = 0;
	}

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
	if (js_val)
		val = json_string_value(js_val);

	return val;
}

static json_t *jwt_b64_decode(char *src)
{
	BIO *b64, *bmem;
	char *buf, *new;
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

	/* Setup the OpenSSL base64 decoder. */
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(new, strlen(new));
	if (!b64 || !bmem) {
		return NULL; // LCOV_EXCL_LINE
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bmem);

	len = BIO_pending(b64);
	if (len <= 0) {
		BIO_free_all(b64);
		return NULL;
	}

	buf = alloca(len);
	if (!buf) {
		BIO_free_all(b64);
		return NULL;
	}

	len = BIO_read(b64, buf, len);
	BIO_free_all(b64);

	buf[len] = '\0';

	return json_loads(buf, 0, NULL);
}

static int jwt_sign_sha_hmac(jwt_t *jwt, BIO *out, const EVP_MD *alg,
			     const char *str)
{
	unsigned char res[jwt->key_len];
	unsigned int res_len;

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)str, strlen(str), res, &res_len);

	BIO_write(out, res, res_len);

	BIO_flush(out);

	return 0;
}

static int jwt_sign(jwt_t *jwt, BIO *out, const char *str)
{
	switch (jwt->alg) {
	case JWT_ALG_NONE:
		return 0;

	case JWT_ALG_HS256:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha256(), str);
	case JWT_ALG_HS384:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha384(), str);
	case JWT_ALG_HS512:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha512(), str);
	}

	return EINVAL; // LCOV_EXCL_LINE
}

static int jwt_parse_body(jwt_t *jwt, char *body)
{
	jwt->grants = jwt_b64_decode(body);
	if (!jwt->grants)
		return EINVAL;

	return 0;
}

static int jwt_verify_head(jwt_t *jwt, char *head)
{
	json_t *js = NULL;
	const char *val;
	int ret;

	js = jwt_b64_decode(head);
	if (!js)
		return EINVAL;

	val = get_js_string(js, "alg");
	ret = jwt_str_alg(jwt, val);
	if (ret)
		goto verify_head_done;

	/* If alg is not NONE, there should be a typ. */
	if (jwt->alg != JWT_ALG_NONE) {
		int len;

		val = get_js_string(js, "typ");
		if (!val || strcasecmp(val, "JWT"))
			ret = EINVAL;

		if (jwt->key) {
			len = jwt_alg_key_len(jwt->alg);
			if (len != jwt->key_len)
				ret = EINVAL;
		} else {
			jwt_scrub_key(jwt);
		}
	}

verify_head_done:
	if (js)
		json_decref(js);

	return ret;
}

static void base64uri_encode(char *str)
{
	int len = strlen(str);
	int i, t;

	for (i = t = 0; i < len; i++) {
		switch (str[i]) {
		case '+':
			str[t] = '-';
			break;
		case '/':
			str[t] = '_';
			break;
		case '=':
			continue;
		}

		t++;
	}

	str[t] = '\0';
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
		goto decode_done; // LCOV_EXCL_LINE
	}

	/* Copy the key over for verify_head. */
	if (key_len) {
		new->key = malloc(key_len);
		if (!new->key) {
			goto decode_done; // LCOV_EXCL_LINE
		}
		memcpy(new->key, key, key_len);
		new->key_len = key_len;
	}

	ret = jwt_verify_head(new, head);
	if (ret)
		goto decode_done;

	ret = jwt_parse_body(new, body);
	if (ret)
		goto decode_done;

	/* Back up a bit so check the sig if needed. */
	if (new->alg != JWT_ALG_NONE) {
		BIO *bmem, *b64;
		char *buf;
		int len;

		b64 = BIO_new(BIO_f_base64());
		bmem = BIO_new(BIO_s_mem());
		if (!b64 || !bmem) {
			// LCOV_EXCL_START
			ret = ENOMEM;
			goto decode_done;
			// LCOV_EXCL_STOP
		}

		BIO_push(b64, bmem);
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

		body[-1] = '.';
		ret = jwt_sign(new, b64, head);
		if (ret)
			goto decode_done;

		len = BIO_pending(bmem);
		if (len < 0) {
			ret = EINVAL;
			goto decode_done;
		}

		buf = alloca(len + 1);
		if (!buf) {
			// LCOV_EXCL_START
			ret = ENOMEM;
			goto decode_done;
			// LCOV_EXCL_STOP
		}

		len = BIO_read(bmem, buf, len);
		BIO_free_all(b64);

		buf[len] = '\0';

		base64uri_encode(buf);

		/* And now... */
		ret = strcmp(buf, sig) ? EINVAL : 0;
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

int jwt_add_grants_json(jwt_t *jwt, const char *json)
{
	json_t *grants = json_loads(json, JSON_REJECT_DUPLICATES, NULL);
	int ret;

	if (grants == NULL)
		return EINVAL;

	ret = json_object_update(jwt->grants, grants);

	json_decref(grants);

	return ret ? EINVAL : 0;
}

int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	json_object_del(jwt->grants, grant);

	return 0;
}

static void jwt_write_bio_head(jwt_t *jwt, BIO *bio, int pretty)
{
	BIO_puts(bio, "{");

	if (pretty)
		BIO_puts(bio, "\n");

	/* An unsecured JWT is a JWS and provides no "typ".
	 * -- draft-ietf-oauth-json-web-token-32 #6. */
	if (jwt->alg != JWT_ALG_NONE) {
		if (pretty)
			BIO_puts(bio, "    ");

		BIO_printf(bio, "\"typ\":%s\"JWT\",", pretty?" ":"");

		if (pretty)
			BIO_puts(bio, "\n");
	}

	if (pretty)
		BIO_puts(bio, "    ");

	BIO_printf(bio, "\"alg\":%s\"%s\"", pretty?" ":"",
		   jwt_alg_str(jwt->alg));

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_puts(bio, "}");

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}

static void jwt_write_bio_body(jwt_t *jwt, BIO *bio, int pretty)
{
	/* Sort keys for repeatability */
	size_t flags = JSON_SORT_KEYS;
	char *serial;

	if (pretty) {
		BIO_puts(bio, "\n");
		flags |= JSON_INDENT(4);
	} else {
		flags |= JSON_COMPACT;
	}

	serial = json_dumps(jwt->grants, flags);

	BIO_puts(bio, serial);

	free(serial);

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}

static void jwt_dump_bio(jwt_t *jwt, BIO *out, int pretty)
{
	jwt_write_bio_head(jwt, out, pretty);
	BIO_puts(out, ".");
	jwt_write_bio_body(jwt, out, pretty);
}

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	BIO *bio;

	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (!bio)
		return ENOMEM;

	jwt_dump_bio(jwt, bio, pretty);

	BIO_free_all(bio);

	return 0;
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
	BIO *bmem = BIO_new(BIO_s_mem());
	char *out;
	int len;

	if (!bmem) {
		// LCOV_EXCL_START
		errno = ENOMEM;
		return NULL;
		// LCOV_EXCL_STOP
	}

	jwt_dump_bio(jwt, bmem, pretty);

	len = BIO_pending(bmem);
	out = malloc(len + 1);
	if (!out) {
		// LCOV_EXCL_START
		BIO_free_all(bmem);
		errno = ENOMEM;
		return NULL;
		// LCOV_EXCL_STOP
	}

	len = BIO_read(bmem, out, len);
	out[len] = '\0';

	BIO_free_all(bmem);
	errno = 0;

	return out;
}

static int jwt_encode_bio(jwt_t *jwt, BIO *out)
{
	BIO *b64, *bmem;
	char *buf;
	int len, len2, ret;

	/* Setup the OpenSSL base64 encoder. */
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	if (!b64 || !bmem) {
		return ENOMEM; // LCOV_EXCL_LINE
	}

	BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	/* First the header. */
	jwt_write_bio_head(jwt, b64, 0);

	BIO_puts(bmem, ".");

	/* Now the body. */
	jwt_write_bio_body(jwt, b64, 0);

	len = BIO_pending(bmem);
	buf = alloca(len + 1);
	if (!buf) {
		// LCOV_EXCL_START
		BIO_free_all(b64);
		return ENOMEM;
		// LCOV_EXCL_STOP
	}

	len = BIO_read(bmem, buf, len);
	buf[len] = '\0';

	base64uri_encode(buf);

	BIO_puts(out, buf);
	BIO_puts(out, ".");

	/* Now the signature. */
	ret = jwt_sign(jwt, b64, buf);
	if (ret)
		goto encode_bio_done;

	len2 = BIO_pending(bmem);
	if (len2 > len) {
		buf = alloca(len2 + 1);
		if (!buf) {
			ret = ENOMEM;
			goto encode_bio_done;
		}
	} else if (len2 < 0) {
		ret = EINVAL;
		goto encode_bio_done;
	}

	len2 = BIO_read(bmem, buf, len2);
	buf[len2] = '\0';

	base64uri_encode(buf);

	BIO_puts(out, buf);

	BIO_flush(out);

	ret = 0;

encode_bio_done:
	/* All done. */
	BIO_free_all(b64);

	return ret;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	BIO *bfp = BIO_new_fp(fp, BIO_NOCLOSE);
	int ret;

	if (!bfp)
		return ENOMEM;

	ret = jwt_encode_bio(jwt, bfp);
	BIO_free_all(bfp);

	return ret;
}

char *jwt_encode_str(jwt_t *jwt)
{
	BIO *bmem = BIO_new(BIO_s_mem());
	char *str = NULL;
	int len;

	if (!bmem) {
		// LCOV_EXCL_START
		errno = ENOMEM;
		return NULL;
		// LCOV_EXCL_STOP
	}

	errno = jwt_encode_bio(jwt, bmem);
	if (errno)
		goto encode_str_done;

	len = BIO_pending(bmem);
	str = malloc(len);
	if (!str) {
		// LCOV_EXCL_START
		errno = ENOMEM;
		goto encode_str_done;
		// LCOV_EXCL_STOP
	}

	len = BIO_read(bmem, str, len);
	str[len] = '\0';

encode_str_done:
	BIO_free_all(bmem);

	return str;
}
