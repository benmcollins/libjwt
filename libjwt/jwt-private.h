/* Copyright (C) 2015-2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#include "config.h"

#include <jansson.h>
#include <time.h>

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
	json_t *headers;
};

struct jwt_valid {
	jwt_alg_t alg;
	time_t now;
	time_t nbf_leeway;
	time_t exp_leeway;
	int hdr;
	json_t *req_grants;
	unsigned int status;
};

/* Crypto operations */
struct jwt_crypto_ops {
	const char *name;
	int (*sign_sha_hmac)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_hmac)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig);
	int (*sign_sha_pem)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_pem)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig_b64);
};

#ifdef HAVE_OPENSSL
extern struct jwt_crypto_ops jwt_openssl_ops;
#endif
#ifdef HAVE_GNUTLS
extern struct jwt_crypto_ops jwt_gnutls_ops;
#endif

/* Memory allocators. */
void *jwt_malloc(size_t size);
void jwt_freemem(void *ptr);

/* Helper routines to handle base64url encoding without percent padding
 * as defined in RFC-4648. */
int jwt_base64uri_encode(char *dst, const char *plain, int plain_len);
void *jwt_base64uri_decode(const char *src, int *ret_len);

/* A time-safe strcmp function */
int jwt_strcmp(const char *str1, const char *str2);

#endif /* JWT_PRIVATE_H */
