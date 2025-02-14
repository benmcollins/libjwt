/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <jwt.h>

#include "jwt-private.h"

/* Library init functionality */
static struct jwt_crypto_ops *jwt_ops_available[] = {
#ifdef HAVE_OPENSSL
	&jwt_openssl_ops,
#endif
#ifdef HAVE_GNUTLS
	&jwt_gnutls_ops,
#endif
#ifdef HAVE_MBEDTLS
	&jwt_mbedtls_ops,
#endif
	NULL,
};

JWT_NO_EXPORT
#if defined HAVE_OPENSSL
struct jwt_crypto_ops *jwt_ops = &jwt_openssl_ops;
#elif defined HAVE_GNUTLS
struct jwt_crypto_ops *jwt_ops = &jwt_gnutls_ops;
#elif defined HAVE_MBEDTLS
struct jwt_crypto_ops *jwt_ops = &jwt_mbedtls_ops;
#else
#error No crypto ops providers are enabled
#endif

const char *jwt_get_crypto_ops(void)
{
	if (jwt_ops == NULL)
		return "(unknown)"; // LCOV_EXCL_LINE

	return jwt_ops->name;
}

jwt_crypto_provider_t jwt_get_crypto_ops_t(void)
{
	if (jwt_ops == NULL)
		return JWT_CRYPTO_OPS_NONE; // LCOV_EXCL_LINE

	return jwt_ops->provider;
}

int jwt_set_crypto_ops_t(jwt_crypto_provider_t opname)
{
	int i;

	/* The user asked for something, let's give it a try */
	for (i = 0; jwt_ops_available[i] != NULL; i++) {
		if (jwt_ops_available[i]->provider != opname)
			continue;

		jwt_ops = jwt_ops_available[i];
		return 0;
	}

	return 1;
}

int jwt_set_crypto_ops(const char *opname)
{
	int i;

	/* The user asked for something, let's give it a try */
	for (i = 0; jwt_ops_available[i] != NULL; i++) {
		if (jwt_strcmp(jwt_ops_available[i]->name, opname))
			continue;

		jwt_ops = jwt_ops_available[i];
		return 0;
	}

	return 1;
}

int jwt_crypto_ops_supports_jwk(void)
{
	return jwt_ops->jwk_implemented ? 1 : 0;
}

JWT_CONSTRUCTOR
void jwt_init()
{
	const char *opname = getenv("JWT_CRYPTO");

	/* By default, we choose the top spot */
	if (opname == NULL || opname[0] == '\0') {
		jwt_ops = jwt_ops_available[0];
		return;
	}

	/* Attempt to set ops */
	if (jwt_set_crypto_ops(opname)) {
		jwt_ops = jwt_ops_available[0];
		fprintf(stderr, "LibJWT: No such crypto ops [%s], falling back to [%s]\n",
			opname, jwt_ops->name);
	}
}
