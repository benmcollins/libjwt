/* Copyright (C) 2015-2017 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#include <jansson.h>

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
	json_t *headers;
};

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
