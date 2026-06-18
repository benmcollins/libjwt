/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
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

	jwt_json_release(__cmd->c.payload);
	jwt_json_release(__cmd->c.headers);

	if (__cmd->c.understood) {
		int i;

		for (i = 0; __cmd->c.understood[i] != NULL; i++)
			jwt_freemem(__cmd->c.understood[i]);
		jwt_freemem(__cmd->c.understood);
	}

	/* @rfc{7515,7.2} Drain the signature list (empty on the compact path). */
	if (__cmd->c.signatures.next != NULL) {
		struct jwt_signature *s, *tmp;

		list_for_each_entry_safe(s, tmp, &__cmd->c.signatures, node) {
			list_del(&s->node);
			jwt_signature_free(s);
		}
	}

	/* @rfc{7797} Free any raw payload (jwt_builder_setpayload()). */
	jwt_scrub_and_free(__cmd->c.payload_raw, __cmd->c.payload_raw_len);

	/* @rfc{8725} Free the checker's typ expectation / algorithm allowlist. */
	jwt_freemem(__cmd->c.expected_typ);
	jwt_freemem(__cmd->c.alg_allowlist);

	memset(__cmd, 0, sizeof(*__cmd));

	jwt_freemem(__cmd);
}

jwt_common_t *FUNC(new)(void)
{
	jwt_common_t *__cmd = jwt_malloc(sizeof(*__cmd));

	if (__cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(__cmd, 0, sizeof(*__cmd));

	/* @rfc{7515,7.2} The signature list is empty until setkey/add_signature
	 * (builder) or the JSON parse (checker) materializes it. */
	INIT_LIST_HEAD(&__cmd->c.signatures);

	/* @rfc{7797} base64url payloads by default (b64=true). */
	__cmd->c.b64 = 1;

	__cmd->c.payload = jwt_json_create();
	__cmd->c.headers = jwt_json_create();
	__cmd->c.claims = CLAIMS_DEF;

	if (!__cmd->c.payload || !__cmd->c.headers) {
		// LCOV_EXCL_START
		jwt_json_release(__cmd->c.payload);
		jwt_json_release(__cmd->c.headers);
		jwt_freemem(__cmd);
		// LCOV_EXCL_STOP
	}

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
		return 1;
	}

	/* Bind algorithm to the JWK's actual key type, not just the
	 * optional "alg" hint. The "alg" parameter on a JWK is optional
	 * (RFC 7517 4.4), so we must never let its absence widen what a
	 * key can be used for. */
	if (alg != JWT_ALG_NONE && jwt_alg_required_kty(alg) != key->kty) {
		jwt_write_error(__cmd,
			"Key type does not match algorithm");
		return 1;
	}

	if (key->alg == JWT_ALG_NONE) {
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

#ifdef JWT_CHECKER
	/* Setting a single key clears any keyring; the last call wins. */
	__cmd->c.keyring = NULL;
#endif

#ifdef JWT_BUILDER
	/* @rfc{7515,7.2} Mirror the primary signer into the first signature, so
	 * a JSON-format build (and any later add_signature) sees it in the list.
	 * Repeated setkey() updates that same first node rather than appending. */
	{
		struct jwt_signature *s = jwt_signature_first_or_add(&__cmd->c);

		if (s == NULL) {
			// LCOV_EXCL_START
			jwt_write_error(__cmd, "Error allocating memory");
			return 1;
			// LCOV_EXCL_STOP
		}
		s->alg = alg;
		s->key = key;
	}
#endif

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

/* @rfc{7519,4.1.7} Register the jti (JWT ID) callback. The builder variant
 * takes a generator (produces an id); the checker variant takes a verifier
 * (validates/consumes one). jti is driven entirely by the callback pointer
 * (jti_gen/jti_check), not by the JWT_CLAIM_JTI bit. Semantics mirror
 * FUNC(setcb): a NULL cb with a non-NULL ctx just updates the ctx; both NULL
 * disables the callback. */
#ifdef JWT_BUILDER
int FUNC(setjti)(jwt_common_t *__cmd, jwt_jti_gen_cb_t cb, void *ctx)
#endif
#ifdef JWT_CHECKER
int FUNC(setjti)(jwt_common_t *__cmd, jwt_jti_check_cb_t cb, void *ctx)
#endif
{
#ifdef JWT_BUILDER
	jwt_jti_gen_cb_t *slot;
#endif
#ifdef JWT_CHECKER
	jwt_jti_check_cb_t *slot;
#endif

	if (__cmd == NULL)
		return 1;

#ifdef JWT_BUILDER
	slot = &__cmd->c.jti_gen;
#endif
#ifdef JWT_CHECKER
	slot = &__cmd->c.jti_check;
#endif

	/* This just updates the CTX */
	if (cb == NULL && *slot != NULL && ctx != NULL) {
		__cmd->c.jti_ctx = ctx;
		return 0;
	}

	if (cb == NULL && ctx != NULL) {
		jwt_write_error(__cmd, "Setting ctx without a cb won't work");
		return 1;
	}

	*slot = cb;
	__cmd->c.jti_ctx = ctx;

	return 0;
}

/* @rfc{7515,4.1.11} Register a "crit" (Critical) header parameter name.
 *
 * For the builder, this is a header the producer wants to mark as critical
 * (emitted in the "crit" array at generation). For the checker, this is a
 * critical header the application understands and is prepared to process.
 *
 * The names are kept in a NULL-terminated, dynamically grown list on the
 * common object. Duplicate registrations are a no-op success.
 */
#ifdef JWT_BUILDER
int FUNC(setcrit)(jwt_common_t *__cmd, const char *header)
#endif
#ifdef JWT_CHECKER
int FUNC(understands)(jwt_common_t *__cmd, const char *header)
#endif
{
	char **grown, *dup;
	size_t count = 0, len;

	if (__cmd == NULL)
		return 1;

	if (header == NULL || !strlen(header)) {
		jwt_write_error(__cmd, "Must pass a header name");
		return 1;
	}

	/* Count existing entries and skip duplicates. */
	if (__cmd->c.understood) {
		for (count = 0; __cmd->c.understood[count] != NULL; count++) {
			if (!strcmp(__cmd->c.understood[count], header))
				return 0;
		}
	}

	/* Grow the list by one (plus the NULL terminator). */
	grown = jwt_malloc((count + 2) * sizeof(char *));
	if (grown == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(__cmd, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	len = strlen(header) + 1;
	dup = jwt_malloc(len);
	if (dup == NULL) {
		// LCOV_EXCL_START
		jwt_freemem(grown);
		jwt_write_error(__cmd, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}
	memcpy(dup, header, len);

	if (__cmd->c.understood) {
		memcpy(grown, __cmd->c.understood, count * sizeof(char *));
		jwt_freemem(__cmd->c.understood);
	}

	grown[count] = dup;
	grown[count + 1] = NULL;
	__cmd->c.understood = grown;

	return 0;
}

typedef enum {
	__HEADER,
	__CLAIM,
} _setget_type_t;

typedef jwt_value_error_t (*__doer_t)(jwt_json_t *, jwt_value_t *);

static jwt_value_error_t __run_it(jwt_common_t *__cmd, _setget_type_t type,
				  jwt_value_t *value, __doer_t doer)
{
	jwt_json_t *which = NULL;
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

	/* Clear any signature state from a prior verify (checker reuse). */
	{
		struct jwt_signature *s, *tmp;

		list_for_each_entry_safe(s, tmp, &__cmd->c.signatures, node) {
			list_del(&s->node);
			jwt_signature_free(s);
		}
		__cmd->c.n_signatures = 0;
		__cmd->c.last_sig_count = 0;
	}

	/* @rfc{7515,7.2} A token whose first non-whitespace byte is '{' is a
	 * JWS JSON Serialization; otherwise it is the Compact form. */
	{
		const char *p = token;

		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (*p == '{')
			return jwt_verify_json(__cmd, token);
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

	/* @rfc{7515,4.1.11} Enforce the "crit" header. Done after the
	 * callback so the application has a chance to inspect the header,
	 * but before any signature work. */
	if (jwt_check_crit(jwt, __cmd->c.understood)) {
		jwt_copy_error(__cmd, jwt);
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

	/* Record the single verified signature so the introspection API
	 * (sig_count/sig_verified/sig_key) works for a Compact token too. */
	if (__cmd->error == 0) {
		struct jwt_signature *s = jwt_signature_append(&__cmd->c);

		if (s != NULL) {
			s->verified = 1;
			s->key = jwt->key;
			s->alg = jwt->alg;
		}
		__cmd->c.last_sig_count = 1;
	}

	return __cmd->error;
}

int jwt_checker_setkeyring(jwt_checker_t *checker, const jwk_set_t *keyring,
			   jwt_verify_policy_t policy)
{
	if (checker == NULL)
		return 1;

	if (keyring == NULL) {
		jwt_write_error(checker, "A keyring is required");
		return 1;
	}

	if (policy != JWT_VERIFY_POLICY_ANY && policy != JWT_VERIFY_POLICY_ALL) {
		jwt_write_error(checker, "Invalid verification policy");
		return 1;
	}

	/* Mutually exclusive with a single key; the last call wins. */
	checker->c.key = NULL;
	checker->c.alg = JWT_ALG_NONE;
	checker->c.keyring = keyring;
	checker->c.policy = policy;

	return 0;
}

int jwt_checker_expect_typ(jwt_checker_t *checker, const char *typ)
{
	char *copy = NULL;

	if (checker == NULL)
		return 1;

	if (typ != NULL) {
		size_t n = strlen(typ) + 1;

		copy = jwt_malloc(n);
		if (copy == NULL) {
			jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}
		memcpy(copy, typ, n);
	}

	jwt_freemem(checker->c.expected_typ);
	checker->c.expected_typ = copy;

	return 0;
}

int jwt_checker_setalgs(jwt_checker_t *checker, const jwt_alg_t *algs, size_t n)
{
	jwt_alg_t *copy = NULL;
	size_t i;

	if (checker == NULL)
		return 1;

	if (algs != NULL && n > 0) {
		for (i = 0; i < n; i++) {
			if (algs[i] >= JWT_ALG_INVAL) {
				jwt_write_error(checker,
					"Invalid algorithm in allowlist");
				return 1;
			}
		}
		copy = jwt_malloc(n * sizeof(jwt_alg_t));
		if (copy == NULL) {
			jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}
		memcpy(copy, algs, n * sizeof(jwt_alg_t));
	}

	jwt_freemem(checker->c.alg_allowlist);
	checker->c.alg_allowlist = copy;
	checker->c.n_alg_allowlist = copy ? n : 0;

	return 0;
}

static const struct jwt_signature *checker_sig_at(const jwt_checker_t *checker,
						  unsigned int index)
{
	const struct jwt_signature *s;
	unsigned int i = 0;

	if (checker == NULL || checker->c.signatures.next == NULL)
		return NULL;

	list_for_each_entry(s, &checker->c.signatures, node) {
		if (i++ == index)
			return s;
	}

	return NULL;
}

unsigned int jwt_checker_sig_count(const jwt_checker_t *checker)
{
	if (checker == NULL)
		return 0;

	return checker->c.last_sig_count;
}

int jwt_checker_sig_verified(const jwt_checker_t *checker, unsigned int index)
{
	const struct jwt_signature *s = checker_sig_at(checker, index);

	return (s != NULL && s->verified) ? 1 : 0;
}

const jwk_item_t *jwt_checker_sig_key(const jwt_checker_t *checker,
				      unsigned int index)
{
	const struct jwt_signature *s = checker_sig_at(checker, index);

	return (s != NULL && s->verified) ? s->key : NULL;
}
#endif

#ifdef JWT_BUILDER
int jwt_builder_set_format(jwt_builder_t *builder, jwt_serialization_t format)
{
	if (builder == NULL)
		return 1;

	if (format != JWT_FORMAT_COMPACT && format != JWT_FORMAT_JSON_FLAT &&
	    format != JWT_FORMAT_JSON_GENERAL) {
		jwt_write_error(builder, "Invalid serialization format");
		return 1;
	}

	builder->c.format = format;

	return 0;
}

int jwt_builder_setpayload(jwt_builder_t *builder, const unsigned char *data,
			   size_t len)
{
	unsigned char *copy = NULL;

	if (builder == NULL)
		return 1;

	if (data != NULL && len > 0) {
		copy = jwt_malloc(len);
		if (copy == NULL) {
			jwt_write_error(builder, "Error allocating memory"); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}
		memcpy(copy, data, len);
	}

	/* Replace any previous raw payload (NULL/0 clears it). */
	jwt_scrub_and_free(builder->c.payload_raw, builder->c.payload_raw_len);
	builder->c.payload_raw = copy;
	builder->c.payload_raw_len = copy ? len : 0;

	return 0;
}

int jwt_builder_setb64(jwt_builder_t *builder, int b64)
{
	if (builder == NULL)
		return 1;

	builder->c.b64 = b64 ? 1 : 0;

	return 0;
}

int jwt_builder_set_detached(jwt_builder_t *builder, int detached)
{
	if (builder == NULL)
		return 1;

	builder->c.detached = detached ? 1 : 0;

	return 0;
}

int jwt_builder_settyp(jwt_builder_t *builder, const char *typ)
{
	jwt_json_t *v;

	if (builder == NULL)
		return 1;

	if (typ == NULL) {
		jwt_json_obj_del(builder->c.headers, "typ");
		return 0;
	}

	v = jwt_json_create_str(typ);
	if (v == NULL || jwt_json_obj_set(builder->c.headers, "typ", v)) {
		jwt_write_error(builder, "Error setting \"typ\" header"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	return 0;
}

jwt_signature_t *jwt_builder_add_signature(jwt_builder_t *builder,
					   jwt_alg_t alg, const jwk_item_t *key)
{
	struct jwt_signature *s;

	if (builder == NULL)
		return NULL;

	if (alg == JWT_ALG_NONE) {
		jwt_write_error(builder,
			"A signature requires an algorithm (not \"none\")");
		return NULL;
	}

	/* Same alg/key validation as setkey (private key, alg<->kty binding,
	 * alg<->key match). */
	if (__setkey_check(builder, alg, key))
		return NULL;

	s = jwt_signature_append(&builder->c);
	if (s == NULL) {
		jwt_write_error(builder, "Error allocating memory"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	s->alg = alg;
	s->key = key;

	/* @rfc{7515,7.2.1} A second signature requires the General JSON form. */
	if (builder->c.n_signatures > 1)
		builder->c.format = JWT_FORMAT_JSON_GENERAL;

	return s;
}

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

	jwt->headers = jwt_json_clone(__cmd->c.headers);
	jwt->claims = jwt_json_clone(__cmd->c.payload);

	/* Our internal work first */
	if (__cmd->c.claims & JWT_CLAIM_IAT) {
		jwt_set_SET_INT(&jval, "iat", (jwt_long_t)tm);
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	if (__cmd->c.claims & JWT_CLAIM_NBF) {
		jwt_set_SET_INT(&jval, "nbf", (jwt_long_t)(tm + __cmd->c.nbf));
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	if (__cmd->c.claims & JWT_CLAIM_EXP) {
		jwt_set_SET_INT(&jval, "exp", (jwt_long_t)(tm + __cmd->c.exp));
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
	}

	/* @rfc{7519,4.1.7} Let the application generate the jti. Done before
	 * the generic callback so the callback can still inspect or override
	 * it. The returned string is set as "jti" and then freed. */
	if (__cmd->c.jti_gen) {
		JWT_CONFIG_DECLARE(jti_config);
		char *jti;

		jti_config.ctx = __cmd->c.jti_ctx;
		jti = __cmd->c.jti_gen(jwt, &jti_config);
		if (jti == NULL) {
			jwt_write_error(__cmd, "jti callback returned no id");
			return NULL;
		}

		jwt_set_SET_STR(&jval, "jti", jti);
		jval.replace = 1;
		jwt_claim_set(jwt, &jval);
		jwt_freemem(jti);
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

	/* @rfc{7797} Thread the unencoded/detached options onto the token. */
	jwt->b64 = __cmd->c.b64;
	jwt->detached = __cmd->c.detached;
	jwt->payload_raw = __cmd->c.payload_raw;
	jwt->payload_raw_len = __cmd->c.payload_raw_len;

	if (!jwt->b64) {
		/* RFC 7797 forbids b64=false for JWTs (JSON claim sets), so it
		 * is only valid over a raw payload. */
		if (jwt->payload_raw == NULL) {
			jwt_write_error(__cmd,
				"b64=false (RFC 7797) requires a raw payload "
				"set with jwt_builder_setpayload()");
			return NULL;
		}
		/* An unencoded payload appears verbatim in the serialized token
		 * (a C string / JSON string), which cannot carry an embedded NUL.
		 * Reject it rather than silently truncate. */
		if (memchr(jwt->payload_raw, '\0', jwt->payload_raw_len) != NULL) {
			jwt_write_error(__cmd,
				"An unencoded (b64=false) payload must not "
				"contain a NUL byte");
			return NULL;
		}
		/* @rfc{7797,6} Emit "b64":false and mark "b64" critical. */
		if (jwt_apply_b64_header(jwt)) {
			jwt_copy_error(__cmd, jwt);
			return NULL;
		}
	}

	/* @rfc{7515,4.1.11} Emit the "crit" header if any were registered.
	 * Done after the callback so it can add the headers being marked. */
	if (jwt_write_crit(jwt, __cmd->c.understood)) {
		jwt_copy_error(__cmd, jwt);
		return NULL;
	}

	/* @rfc{7515,7.2} JSON Serialization (one or more signatures). */
	if (__cmd->c.format != JWT_FORMAT_COMPACT) {
		if (__cmd->c.n_signatures == 0) {
			jwt_write_error(__cmd, "No key set for JSON serialization");
			return NULL;
		}
		if (__cmd->c.format == JWT_FORMAT_JSON_FLAT &&
		    __cmd->c.n_signatures > 1) {
			jwt_write_error(__cmd,
				"Flattened serialization allows only one signature");
			return NULL;
		}

		out = jwt_encode_json(jwt, &__cmd->c);
		jwt_copy_error(__cmd, jwt);
		return out;
	}

	/* @rfc{7515,7.1} Compact Serialization carries exactly one signature. */
	if (__cmd->c.n_signatures > 1) {
		jwt_write_error(__cmd,
			"Compact serialization cannot carry multiple signatures");
		return NULL;
	}

	if (jwt_head_setup(jwt))
		return NULL; // LCOV_EXCL_LINE

	out = jwt_encode_str(jwt);
	jwt_copy_error(__cmd, jwt);

	return out;
}
#endif
