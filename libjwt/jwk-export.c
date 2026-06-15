/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Backend-neutral native-key -> JWK conversion (the inverse of the process_*
 * JWK parsers). The crypto-specific work of parsing a PEM/DER blob and
 * extracting its raw components is delegated to the active backend's
 * key2jwk_params op (implemented in openssl/, gnutls/, and mbedtls/); this file
 * assembles the resulting jwk_export_t into a JWK JSON object and handles the
 * pieces that need no crypto: kid generation, use/key_ops, base64url encoding,
 * and the raw-bytes HMAC ("oct") fallback. The produced JSON is routed back
 * through the normal jwks_load() machinery so the jwk_item_t is built exactly
 * as for a parsed JWKS. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <jwt.h>
#include "jwt-private.h"

/* Generate an RFC 4122 version 4 UUID string into the caller's buffer (which
 * must be at least 37 bytes), using the active backend's CSPRNG. Returns 0 on
 * success. */
static int uuidv4(char out[37])
{
	uint8_t b[16];

	if (jwt_ops->rng == NULL || jwt_ops->rng(b, sizeof(b)))
		return -1; // LCOV_EXCL_LINE

	/* version 4 and RFC 4122 variant */
	b[6] = (b[6] & 0x0F) | 0x40;
	b[8] = (b[8] & 0x3F) | 0x80;

	snprintf(out, 37,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

	return 0;
}

/* For HMAC keys: treat the raw bytes as an "oct" key, guessing the alg from the
 * key length. */
static void process_hmac_key(jwt_json_t *jwk, const unsigned char *key,
			     size_t len)
{
	char *b64;

	jwt_json_obj_set(jwk, "kty", jwt_json_create_str("oct"));

	if (jwt_base64uri_encode(&b64, (const char *)key, (int)len) > 0) {
		jwt_json_obj_set(jwk, "k", jwt_json_create_str(b64));
		jwt_freemem(b64);
	}

	if (len >= 32 && len < 48)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS256"));
	else if (len >= 48 && len < 64)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS384"));
	else if (len >= 64)
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str("HS512"));
}

static const char *kty_str(jwk_key_type_t kty)
{
	switch (kty) {
	case JWK_KEY_TYPE_RSA:
		return "RSA";
	case JWK_KEY_TYPE_EC:
		return "EC";
	case JWK_KEY_TYPE_OKP:
		return "OKP";
	default:
		return NULL; // LCOV_EXCL_LINE
	}
}

/* Free and scrub the component buffers a backend allocated into @kp. */
static void jwk_export_clear(jwk_export_t *kp)
{
	int i;

	for (i = 0; i < kp->nparams; i++)
		jwt_scrub_and_free(kp->params[i].data, kp->params[i].len);

	kp->nparams = 0;
}

int jwt_key2jwk(const char *key, size_t len, unsigned int flags,
		jwt_json_t *out_array)
{
	jwk_export_t kp;
	jwt_json_t *jwk, *ops;
	const char *kty;
	char kid[37];
	int r, i;

	memset(&kp, 0, sizeof(kp));

	/* Try to parse it as an asymmetric key via the active backend. */
	r = (jwt_ops->key2jwk_params != NULL)
		? jwt_ops->key2jwk_params(key, len, &kp) : 1;

	/* Not a parseable key: optionally fall back to a raw HMAC ("oct") key. */
	if (r != 0 && !(flags & JWK_KEY_TRY_HMAC)) {
		jwk_export_clear(&kp);
		return -1;
	}

	jwk = jwt_json_create();
	if (jwk == NULL) {
		// LCOV_EXCL_START
		jwk_export_clear(&kp);
		return -1;
		// LCOV_EXCL_STOP
	}

	/* A public key is marked use=sig; a private (or HMAC) key gets key_ops. */
	if (r == 0 && !kp.is_private) {
		jwt_json_obj_set(jwk, "use", jwt_json_create_str("sig"));
	} else {
		ops = jwt_json_create_arr();
		jwt_json_arr_append(ops, jwt_json_create_str("sign"));
		jwt_json_obj_set(jwk, "key_ops", ops);
	}

	if ((flags & JWK_KEY_GEN_KID) && uuidv4(kid) == 0)
		jwt_json_obj_set(jwk, "kid", jwt_json_create_str(kid));

	/* HMAC fallback for unparseable input. */
	if (r != 0) {
		jwk_export_clear(&kp);
		process_hmac_key(jwk, (const unsigned char *)key, len);
		jwt_json_arr_append(out_array, jwk);
		return 0;
	}

	kty = kty_str(kp.kty);
	if (kty == NULL) {
		// LCOV_EXCL_START
		jwk_export_clear(&kp);
		jwt_json_releasep(&jwk);
		return -1;
		// LCOV_EXCL_STOP
	}

	jwt_json_obj_set(jwk, "kty", jwt_json_create_str(kty));
	if (kp.alg[0])
		jwt_json_obj_set(jwk, "alg", jwt_json_create_str(kp.alg));
	if (kp.crv[0])
		jwt_json_obj_set(jwk, "crv", jwt_json_create_str(kp.crv));

	for (i = 0; i < kp.nparams; i++) {
		char *b64;

		if (kp.params[i].data == NULL || kp.params[i].len == 0)
			continue; // LCOV_EXCL_LINE

		if (jwt_base64uri_encode(&b64, (char *)kp.params[i].data,
					 (int)kp.params[i].len) > 0) {
			jwt_json_obj_set(jwk, kp.params[i].name,
					 jwt_json_create_str(b64));
			jwt_freemem(b64);
		}
	}

	jwk_export_clear(&kp);
	jwt_json_arr_append(out_array, jwk);

	return 0;
}
