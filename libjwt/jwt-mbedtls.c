/* Copyright (C) 2015-2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <errno.h>
#include <mbedtls/ssl.h>

#include <jwt.h>

#include "jwt-private.h"

static int mbedtls_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
				 const char *str, unsigned int str_len)
{
	return EINVAL;

}

static int mbedtls_verify_sha_hmac(jwt_t *jwt, const char *head,
				   unsigned int head_len, const char *sig)
{
	return EINVAL;
}

static int mbedtls_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
				const char *str, unsigned int str_len)
{
	return EINVAL;
}

static int mbedtls_verify_sha_pem(jwt_t *jwt, const char *head,
				  unsigned int head_len, const char *sig_b64)
{
	return EINVAL;
}

int mbedtls_process_eddsa(json_t *jwk, jwk_item_t *item);
int mbedtls_process_rsa(json_t *jwk, jwk_item_t *item);
int mbedtls_process_ec(json_t *jwk, jwk_item_t *item);
void mbedtls_process_item_free(jwk_item_t *item);

/* Export our ops */
struct jwt_crypto_ops jwt_mbedtls_ops = {
	.name			= "mbedtls",
	.provider		= JWT_CRYPTO_OPS_MBEDTLS,

	.sign_sha_hmac		= mbedtls_sign_sha_hmac,
	.verify_sha_hmac	= mbedtls_verify_sha_hmac,
	.sign_sha_pem		= mbedtls_sign_sha_pem,
	.verify_sha_pem		= mbedtls_verify_sha_pem,

	/* Needs to be implemented */
	.jwk_implemented	= 0,
	.process_eddsa		= mbedtls_process_eddsa,
	.process_rsa		= mbedtls_process_rsa,
	.process_ec		= mbedtls_process_ec,
	.process_item_free	= mbedtls_process_item_free,
};
