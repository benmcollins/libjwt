/* Copyright (C) 2015-2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jansson.h>
#include <time.h>
#include <stdarg.h>

#include "ll.h"

extern struct jwt_crypto_ops *jwt_ops;

#define jwks_write_error(__obj, __fmt, __args...)		\
({								\
	snprintf(__obj->error_msg, sizeof(__obj->error_msg),	\
		 __fmt, ##__args);				\
	item->error = 1;					\
})

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

/* Yes, this is a bit of overhead, but it keeps me from having to
 * expose list.h in jwt.h. */
typedef struct jwk_list_item {
	ll_t node;
	jwk_item_t *item;
} jwk_list_item_t;

struct jwk_set {
	ll_t head;
	int error;
	char error_msg[256];
};

/* Crypto operations */
struct jwt_crypto_ops {
	const char *name;
	jwt_crypto_provider_t provider;

	/* Signing/Verifying */
	int (*sign_sha_hmac)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_hmac)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig);
	int (*sign_sha_pem)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_pem)(jwt_t *jwt, const char *head,
		unsigned int head_len, const char *sig_b64);

	/* Parsing a JWK to prepare it for use */
	int jwk_implemented;
	int (*process_eddsa)(json_t *jwk, jwk_item_t *item);
	int (*process_rsa)(json_t *jwk, jwk_item_t *item);
	int (*process_ec)(json_t *jwk, jwk_item_t *item);
	void (*process_item_free)(jwk_item_t *item);
};

#ifdef HAVE_OPENSSL
extern struct jwt_crypto_ops jwt_openssl_ops;
#endif
#ifdef HAVE_GNUTLS
extern struct jwt_crypto_ops jwt_gnutls_ops;
#endif
#ifdef HAVE_MBEDTLS
extern struct jwt_crypto_ops jwt_mbedtls_ops;
#endif

/* Memory allocators. */
void *jwt_malloc(size_t size);
void jwt_freemem(void *ptr);

/* Helper routines to handle base64url encoding without percent padding
 * as defined in RFC-4648. */
int jwt_base64uri_encode(char **_dst, const char *plain, int plain_len);
void *jwt_base64uri_decode(const char *src, int *ret_len);

/* A time-safe strcmp function */
int jwt_strcmp(const char *str1, const char *str2);

#endif /* JWT_PRIVATE_H */
