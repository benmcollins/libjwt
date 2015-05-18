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

#include <jwt.h>

#include "config.h"

/* Singly linked list of key and value pairs. */
struct jwt_grant {
	char *key;
	char *val;
	struct jwt_grant *next;
};

struct jwt {
	jwt_alg_t alg;
	struct jwt_grant *grants;
};

static const char *jwt_alg_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	}

	/* Should never be reached. */
	return NULL;
}

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
	case JWT_ALG_HS256:
		jwt->alg = alg;
		return 0;
	}

	return EINVAL;
}

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = malloc(sizeof(jwt_t));
	if (!*jwt)
		return ENOMEM;

	memset(*jwt, 0, sizeof(jwt_t));

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	struct jwt_grant *jlist, *side;

	if (!jwt)
		return;

	jlist = jwt->grants;
	while (jlist) {
		side = jlist;
		jlist = side->next;

		free(side->key);
		free(side->val);
		free(side);
	}

	free(jwt);
}

const char *jwt_get_grant(jwt_t *jwt, const char *grant)
{
	struct jwt_grant *jlist;

	if (!grant || !strlen(grant))
		return NULL;

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (!strcmp(jlist->key, grant))
			return jlist->val;
	}

	return NULL;
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	struct jwt_grant *jlist;

	/* Allow the value to be empty. */
	if (!grant || !strlen(grant) || !val)
		return EINVAL;

	if (jwt_get_grant(jwt, grant) != NULL)
		return EEXIST;

	jlist = malloc(sizeof(*jlist));
	if (!jlist)
		return ENOMEM;

	memset(jlist, 0, sizeof(*jlist));
	jlist->key = strdup(grant);
	jlist->val = strdup(val);
	jlist->next = jwt->grants;
	jwt->grants = jlist;

	return 0;
}

int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	struct jwt_grant *jlist, *side = NULL;

	if (!grant || !strlen(grant))
		return EINVAL;

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (!strcmp(jlist->key, grant))
			break;
		/* Track the last one. */
		side = jlist;
	}

	/* If it ain't here, then we ok wit dat. */
	if (!jlist)
		return 0;

	if (side)
		side->next = jlist->next;
	else
		jwt->grants = jlist->next;

	free(jlist->key);
	free(jlist->val);
	free(jlist);

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

		BIO_puts(bio, "\"typ\":\"JWT\",");

		if (pretty)
			BIO_puts(bio, "\n");
	}

	if (pretty)
		BIO_puts(bio, "    ");

	BIO_printf(bio, "\"alg\":\"%s\"", jwt_alg_str(jwt->alg));

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_puts(bio, "}");

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}

static void jwt_write_bio_body(jwt_t *jwt, BIO *bio, int pretty)
{
	struct jwt_grant *jlist;

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_puts(bio, "{");

	if (pretty)
		BIO_puts(bio, "\n");

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (pretty)
			BIO_puts(bio, "    ");

		BIO_printf(bio, "\"%s\":\"%s\"", jlist->key, jlist->val);

		if (jlist->next)
			BIO_puts(bio, ",");

		if (pretty)
			BIO_puts(bio, "\n");
	}

	BIO_puts(bio, "}");

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	BIO *bio;

	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (!bio)
		return ENOMEM;

	jwt_write_bio_head(jwt, bio, pretty);

	BIO_puts(bio, ".");

	jwt_write_bio_body(jwt, bio, pretty);

	BIO_flush(bio);

	BIO_free_all(bio);

	return 0;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	BIO *bio, *b64;

	/* Setup the OpenSSL base64 encoder. */
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (!b64 || !bio)
		return ENOMEM;

	BIO_push(b64, bio);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	/* Print the header first. */
	jwt_write_bio_head(jwt, b64, 0);

	BIO_puts(bio, ".");

	/* Now the body. */
	jwt_write_bio_body(jwt, b64, 0);

	BIO_puts(bio, ".");

	/* Now the signature. */
	if (jwt->alg != JWT_ALG_NONE)
		/* TODO */;

	BIO_flush(b64);

	/* All done. */
	BIO_free_all(b64);

	return 0;
}
