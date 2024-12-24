/* Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
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

#ifndef ARRAY_SIZE
#  ifdef __GNUC__
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]) + \
	__builtin_types_compatible_p(typeof(__arr), typeof(&(__arr)[0])) * 0)
#  else
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]))
#  endif
#endif

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
	jwt_valid_exception_t status;
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
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_openssl_ops;
#endif
#ifdef HAVE_GNUTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_gnutls_ops;
#endif
#ifdef HAVE_MBEDTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_mbedtls_ops;
#endif

/* Memory allocators. */
JWT_NO_EXPORT
void *jwt_malloc(size_t size);
JWT_NO_EXPORT
void __jwt_freemem(void *ptr);
JWT_NO_EXPORT
void *jwt_realloc(void *ptr, size_t size);

#define jwt_freemem(__ptr) ({		\
	if (__ptr) {			\
		__jwt_freemem(__ptr);	\
		__ptr = NULL;		\
	}				\
})

/* Helper routines to handle base64url encoding without percent padding
 * as defined in RFC-4648. */
JWT_NO_EXPORT
int jwt_base64uri_encode(char **_dst, const char *plain, int plain_len);
JWT_NO_EXPORT
void *jwt_base64uri_decode(const char *src, int *ret_len);

/* JSON stuff */
JWT_NO_EXPORT
const char *get_js_string(json_t *js, const char *key);
JWT_NO_EXPORT
long get_js_int(json_t *js, const char *key);
JWT_NO_EXPORT
int get_js_bool(json_t *js, const char *key);

/* A time-safe strcmp function */
JWT_NO_EXPORT
int jwt_strcmp(const char *str1, const char *str2);

JWT_NO_EXPORT
char *jwt_strdup(const char *str);

JWT_NO_EXPORT
void jwt_scrub_key(jwt_t *jwt);

JWT_NO_EXPORT
int jwt_verify_sig(jwt_t *jwt, const char *head, unsigned int head_len,
                   const char *sig);
JWT_NO_EXPORT
int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str,
	     unsigned int str_len);

JWT_NO_EXPORT
int __append_str(char **buf, const char *str);

#endif /* JWT_PRIVATE_H */
