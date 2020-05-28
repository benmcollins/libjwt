/* Copyright (C) 2015-2017 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#include <jansson.h>
#include <time.h>

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
	json_t *headers;

	/* This structure holds related data fields needed in case
	 * a signature needs to be checked by jwt_check_signature(). */
	struct {
		/* A pointer to the token string as passed to 'jwt_decode()'.
		 * This is needed in case a signature check is requested at
		 * a later time, after 'jwt_decode()'. The 'head' and 'sig'
		 * fields below point to the header and signature fields of the
		 * token text, respectively, and are needed in case of a
		 * signature verification request. */
		unsigned char * token_data;
		/* The size of the data block pointed to by the 'token_data' field. */
		size_t data_len;
		/* A pointer to the signature bytes, it points inside the 'token_data'
		 * block above, and should not be individually 'free()'-d. */
		const unsigned char * sig;
	} sig_data;
};

struct jwt_valid {
	jwt_alg_t alg;
	time_t now;
	int hdr;
	json_t *req_grants;
	unsigned int status;
};

/* Memory allocators. */
void *jwt_malloc(size_t size);
void jwt_freemem(void *ptr);

/* Helper routines. */
void jwt_base64uri_encode(char *str);
void *jwt_b64_decode(const char *src, int *ret_len);

/* These routines are implemented by the crypto backend. */
int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
		      const char *str);

int jwt_verify_sha_hmac(jwt_t *jwt, const char *head, const char *sig);

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
		     const char *str);

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64);

#endif /* JWT_PRIVATE_H */
