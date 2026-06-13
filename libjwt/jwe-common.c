/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* XXX This file is used to generate jwe-builder.i and jwe-checker.i */

#ifdef JWE_BUILDER
#define jwe_common_t	jwe_builder_t
#define FUNC(__x)	jwe_builder_##__x
#endif

#ifdef JWE_CHECKER
#define jwe_common_t	jwe_checker_t
#define FUNC(__x)	jwe_checker_##__x
#endif

#ifndef jwe_common_t
#error Must have target defined
#endif

void FUNC(free)(jwe_common_t *__cmd)
{
	if (__cmd == NULL)
		return;

	jwt_json_release(__cmd->c.payload);
	jwt_json_release(__cmd->c.headers);

	/* Scrub sensitive key material. The CEK is secret; the other
	 * components are not, but free them all here. */
	jwt_scrub_and_free(__cmd->c.cek, __cmd->c.cek_len);
	jwt_freemem(__cmd->c.enckey);
	jwt_freemem(__cmd->c.iv);
	jwt_freemem(__cmd->c.ct);
	jwt_freemem(__cmd->c.tag);

	memset(__cmd, 0, sizeof(*__cmd));

	jwt_freemem(__cmd);
}

jwe_common_t *FUNC(new)(void)
{
	jwe_common_t *__cmd = jwt_malloc(sizeof(*__cmd));

	if (__cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(__cmd, 0, sizeof(*__cmd));

	__cmd->c.payload = jwt_json_create();
	__cmd->c.headers = jwt_json_create();

	if (!__cmd->c.payload || !__cmd->c.headers) {
		// LCOV_EXCL_START
		jwt_json_release(__cmd->c.payload);
		jwt_json_release(__cmd->c.headers);
		jwt_freemem(__cmd);
		return NULL;
		// LCOV_EXCL_STOP
	}

	return __cmd;
}

int FUNC(error)(const jwe_common_t *__cmd)
{
	if (__cmd == NULL)
		return 1;

	return __cmd->error ? 1 : 0;
}

const char *FUNC(error_msg)(const jwe_common_t *__cmd)
{
	if (__cmd == NULL)
		return NULL;

	return __cmd->error_msg;
}

void FUNC(error_clear)(jwe_common_t *__cmd)
{
	if (__cmd == NULL)
		return;

	__cmd->error = 0;
	__cmd->error_msg[0] = '\0';
}

int FUNC(setkey)(jwe_common_t *__cmd, jwe_key_alg_t alg, jwe_enc_t enc,
		 const jwk_item_t *key)
{
	const char *reason;

	if (__cmd == NULL)
		return 1;

	if (alg == JWE_ALG_NONE || alg >= JWE_ALG_INVAL) {
		jwt_write_error(__cmd, "Invalid JWE key management alg");
		return 1;
	}

	if (enc == JWE_ENC_NONE || enc >= JWE_ENC_INVAL) {
		jwt_write_error(__cmd, "Invalid JWE content encryption enc");
		return 1;
	}

	if (key == NULL) {
		jwt_write_error(__cmd, "JWE requires a key");
		return 1;
	}

	/* @rfc{7516,11.4} Enforce key-usage gating. The builder is the producer
	 * (encrypt/wrap); the checker is the consumer (decrypt/unwrap). */
#ifdef JWE_BUILDER
	reason = jwe_key_usage_check(key, alg, 1);
#else
	reason = jwe_key_usage_check(key, alg, 0);
#endif
	if (reason != NULL) {
		jwt_write_error(__cmd, "%s", reason);
		return 1;
	}

	__cmd->c.key_alg = alg;
	__cmd->c.enc = enc;
	__cmd->c.key = key;

	return 0;
}
