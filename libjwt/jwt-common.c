/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* XXX This file is used to generate jwt-builder.i and jwt-checker.i */

#ifdef JWT_BUILDER
#define jwt_common_t	jwt_builder_t
#define FUNC(__x)	jwt_builder_##__x
#define CLAIMS_DEF	JWT_CLAIM_IAT
#define __DISABLE	0
#endif

#ifdef JWT_CHECKER
#define jwt_common_t	jwt_checker_t
#define FUNC(__x)	jwt_checker_##__x
#define CLAIMS_DEF	(JWT_CLAIM_EXP | JWT_CLAIM_NBF)
#define __DISABLE	-1
#endif

#ifndef jwt_common_t
#error Must have target defined
#endif

void FUNC(free)(jwt_common_t *__cmd)
{
	if (__cmd == NULL)
		return;

	json_decref(__cmd->c.payload);
	json_decref(__cmd->c.headers);

	memset(__cmd, 0, sizeof(*__cmd));

	jwt_freemem(__cmd);
}

jwt_common_t *FUNC(new)(void)
{
	jwt_common_t *__cmd = jwt_malloc(sizeof(*__cmd));

	if (__cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(__cmd, 0, sizeof(*__cmd));

	__cmd->c.payload = json_object();
	__cmd->c.headers = json_object();
	__cmd->c.claims = CLAIMS_DEF;

	if (!__cmd->c.payload || !__cmd->c.headers)
		jwt_freemem(__cmd); // LCOV_EXCL_LINE

	return __cmd;
}

static int __setkey_check(jwt_common_t *__cmd, const jwt_alg_t alg,
		       const jwk_item_t *key)
{
	if (__cmd == NULL)
		return 1;

#ifdef JWT_BUILDER
	if (key && !key->is_private_key) {
		jwt_write_error(__cmd, "Signing requires a private key");
		return 1;
	}
#endif
	/* TODO: Check key_ops and use */

	if (key == NULL) {
		if (alg == JWT_ALG_NONE)
			return 0;

		jwt_write_error(__cmd, "Cannot set alg without a key");
	} else if (key->alg == JWT_ALG_NONE) {
		if (alg != JWT_ALG_NONE)
			return 0;

		jwt_write_error(__cmd, "Key provided, but could not find alg");
	} else {
		if (alg == JWT_ALG_NONE)
			return 0;

		if (alg == key->alg)
			return 0;

		jwt_write_error(__cmd, "Alg mismatch");
	}

	return 1;
}

int FUNC(setkey)(jwt_common_t *__cmd, const jwt_alg_t alg,
		 const jwk_item_t *key)
{
	if (__setkey_check(__cmd, alg, key))
		return 1;

	__cmd->c.alg = alg;
	__cmd->c.key = key;

	return 0;
}

int FUNC(error)(const jwt_common_t *__cmd)
{
	if (__cmd == NULL)
		return 1;

	return __cmd->error ? 1 : 0;
}

const char *FUNC(error_msg)(const jwt_common_t *__cmd)
{
	if (__cmd == NULL)
		return NULL;

	return __cmd->error_msg;
}

void FUNC(error_clear)(jwt_common_t *__cmd)
{
	if (__cmd == NULL)
		return;

	__cmd->error = 0;
	__cmd->error_msg[0] = '\0';
}

#ifdef JWT_BUILDER
int FUNC(enable_iat)(jwt_common_t *__cmd, int enable)
{
	int orig;

	if (!__cmd)
		return -1;

	orig = __cmd->c.claims & JWT_CLAIM_IAT ? 1 : 0;

	if (enable)
		__cmd->c.claims |= JWT_CLAIM_IAT;
	else
		__cmd->c.claims &= ~JWT_CLAIM_IAT;

	return orig;
}
#endif

int FUNC(setcb)(jwt_common_t *__cmd, jwt_callback_t cb, void *ctx)
{
	if (__cmd == NULL)
		return 1;

	/* This just updates the CTX */
	if (cb == NULL && __cmd->c.cb != NULL && ctx != NULL) {
		__cmd->c.cb_ctx = ctx;
		return 0;
	}

	if (cb == NULL && ctx != NULL) {
		jwt_write_error(__cmd, "Setting ctx without a cb won't work");
		return 1;
	}

	__cmd->c.cb = cb;
	__cmd->c.cb_ctx = ctx;

	return 0;
}

void *FUNC(getctx)(jwt_common_t *__cmd)
{
	if (__cmd == NULL)
		return NULL;

	return __cmd->c.cb_ctx;
}

typedef enum {
	__HEADER,
	__CLAIM,
} _setget_type_t;

typedef jwt_value_error_t (*__doer_t)(json_t *, jwt_value_t *);

static jwt_value_error_t __run_it(jwt_common_t *__cmd, _setget_type_t type,
				  jwt_value_t *value, __doer_t doer)
{
	json_t *which = NULL;
#ifdef JWT_BUILDER
	if (!__cmd || !value) {
		if (value)
			return value->error = JWT_VALUE_ERR_INVALID;
		return JWT_VALUE_ERR_INVALID;
	}
#endif
	switch (type) {
#ifdef JWT_BUILDER
	case __HEADER:
		which = __cmd->c.headers;
		break;
#endif
	case __CLAIM:
		which = __cmd->c.payload;
		break;
	// LCOV_EXCL_START
	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	// LCOV_EXCL_STOP
	}

	return doer(which, value);
}

#ifdef JWT_BUILDER
/* Claims */
jwt_value_error_t FUNC(claim_get)(jwt_common_t *__cmd, jwt_value_t *value)
{
	return __run_it(__cmd, __CLAIM, value, __getter);
}

jwt_value_error_t FUNC(claim_set)(jwt_common_t *__cmd, jwt_value_t *value)
{
	return __run_it(__cmd, __CLAIM, value, __setter);
}

jwt_value_error_t FUNC(claim_del)(jwt_common_t *__cmd, const char *claim)
{
	if (!__cmd)
		return JWT_VALUE_ERR_INVALID;
	return __deleter(__cmd->c.payload, claim);
}

/* Headers */
jwt_value_error_t FUNC(header_get)(jwt_common_t *__cmd, jwt_value_t *value)
{
	return __run_it(__cmd, __HEADER, value, __getter);
}

jwt_value_error_t FUNC(header_set)(jwt_common_t *__cmd, jwt_value_t *value)
{
	return __run_it(__cmd, __HEADER, value, __setter);
}

jwt_value_error_t FUNC(header_del)(jwt_common_t *__cmd, const char *header)
{
	if (!__cmd)
		return JWT_VALUE_ERR_INVALID;
	return __deleter(__cmd->c.headers, header);
}
#endif

#ifdef JWT_CHECKER
/* Just a few types of claims */
static const char *__get_name(jwt_claims_t type)
{
	if (type == JWT_CLAIM_ISS)
		return "iss";
	else if (type == JWT_CLAIM_AUD)
		return "aud";
	else if (type == JWT_CLAIM_SUB)
		return "sub";
	return NULL;
}

const char *FUNC(claim_get)(jwt_common_t *__cmd, jwt_claims_t type)
{
	const char *name = NULL;
	jwt_value_t jval;

	if (!__cmd)
		return NULL;

	name = __get_name(type);
	if (name == NULL)
		return NULL;

	jwt_set_GET_STR(&jval, name);
	__run_it(__cmd, __CLAIM, &jval, __getter);

	/* Ignore errors, just return a string or NULL */
	return jval.str_val;
}

int FUNC(claim_set)(jwt_common_t *__cmd, jwt_claims_t type, const char *value)
{
	const char *name = NULL;
	jwt_value_t jval;

	if (!__cmd || !value)
		return 1;

	name = __get_name(type);
	if (name == NULL)
		return 1;

	__cmd->c.claims |= type;

	jwt_set_SET_STR(&jval, name, value);
	jval.replace = 1;

	return __run_it(__cmd, __CLAIM, &jval, __setter) ? 1 : 0;
}

int FUNC(claim_del)(jwt_common_t *__cmd, jwt_claims_t type)
{
	const char *name = NULL;

	if (!__cmd)
		return 1;

	name = __get_name(type);
	if (name == NULL)
		return 1;

	__cmd->c.claims &= ~type;

	return __deleter(__cmd->c.payload, name);
}
#endif

/* Time offsets */
#ifdef JWT_BUILDER
int FUNC(time_offset)(jwt_common_t *__cmd, jwt_claims_t claim, time_t secs)
#endif
#ifdef JWT_CHECKER
int FUNC(time_leeway)(jwt_common_t *__cmd, jwt_claims_t claim, time_t secs)
#endif
{
	if (!__cmd)
		return 1;

	switch (claim) {
	case JWT_CLAIM_EXP:
		__cmd->c.exp = secs;
		break;

	case JWT_CLAIM_NBF:
		__cmd->c.nbf = secs;
		break;

	default:
		return 1;
	}

	if (secs <= __DISABLE)
		__cmd->c.claims &= ~claim;
	else
		__cmd->c.claims |= claim;

	return 0;
}

#ifdef JWT_CHECKER
int FUNC(verify)(jwt_common_t *__cmd, const char *token)
{
	JWT_CONFIG_DECLARE(config);
	unsigned int payload_len;
	jwt_auto_t *jwt = NULL;

	if (__cmd == NULL)
		return 1;

	if (token == NULL || !strlen(token)) {
		jwt_write_error(__cmd, "Must pass a token");
		return 1;
	}

	jwt = jwt_new();
	if (jwt == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(__cmd, "Could not allocate JWT object");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* First parsing pass, error will be set for us */
        if (jwt_parse(jwt, token, &payload_len)) {
		jwt_copy_error(__cmd, jwt);
		return 1;
	};

	config.key = __cmd->c.key;
	config.alg = __cmd->c.alg;
	config.ctx = __cmd->c.cb_ctx;

	/* Let the user handle this and update config */
        if (__cmd->c.cb && __cmd->c.cb(jwt, &config)) {
		jwt_write_error(__cmd, "User callback returned error");
		return 1;
	}

	/* Callback may have changed this */
        if (__setkey_check(__cmd, config.alg, config.key))
		return 1;

	jwt->key = config.key;
	jwt->checker = __cmd;

	/* Finish it up */
	jwt = jwt_verify_complete(jwt, &config, token, payload_len);

	/* Copy any errors back */
	jwt_copy_error(__cmd, jwt);

	return __cmd->error;
}
#endif

#ifdef JWT_BUILDER
char *FUNC(generate)(jwt_common_t *__cmd)
{
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;
	char *out = NULL;
	jwt_value_t jval;
	time_t tm = time(NULL);

	if (__cmd == NULL)
		return NULL;

	jwt = jwt_malloc(sizeof(*jwt));
	if (jwt == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(jwt, 0, sizeof(*jwt));

	jwt->headers = json_deep_copy(__cmd->c.headers);
	jwt->claims = json_deep_copy(__cmd->c.payload);

	/* Our internal work first */
	if (__cmd->c.claims & JWT_CLAIM_IAT) {
		jwt_set_SET_INT(&jval, "iat", (long)tm);
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	if (__cmd->c.claims & JWT_CLAIM_NBF) {
		jwt_set_SET_INT(&jval, "nbf", (long)(tm + __cmd->c.nbf));
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	if (__cmd->c.claims & JWT_CLAIM_EXP) {
		jwt_set_SET_INT(&jval, "exp", (long)(tm + __cmd->c.exp));
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	/* Alg and key checks */
	config.alg = __cmd->c.alg;
	if (config.alg == JWT_ALG_NONE && __cmd->c.key)
		config.alg = __cmd->c.key->alg;
	config.key = __cmd->c.key;
	config.ctx = __cmd->c.cb_ctx;

	/* Let the callback do it's thing */
	if (__cmd->c.cb && __cmd->c.cb(jwt, &config)) {
		jwt_write_error(__cmd, "User callback returned error");
		return NULL;
	}

	/* Callback may have changed this */
	if (__setkey_check(__cmd, config.alg, config.key)) {
		jwt_write_error(__cmd, "Algorithm and key returned by callback invalid");
		return NULL;
	}

	jwt->alg = config.alg;
	jwt->key = config.key;

	if (jwt_head_setup(jwt))
		return NULL; // LCOV_EXCL_LINE

	out = jwt_encode_str(jwt);
	jwt_copy_error(__cmd, jwt);

	return out;
}
#endif
