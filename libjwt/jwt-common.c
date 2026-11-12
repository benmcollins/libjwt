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

	/* @rfc{9068} Free the required-claims list (the embedded_keyring is
	 * borrowed, like the verify keyring, so it is never freed here). */
	if (__cmd->c.require != NULL) {
		size_t i;

		for (i = 0; i < __cmd->c.n_require; i++)
			jwt_freemem(__cmd->c.require[i]);
		jwt_freemem(__cmd->c.require);
	}
	jwt_freemem(__cmd->c.embedded_jkt);
	if (__cmd->c.embedded_owned != NULL)
		jwks_free(__cmd->c.embedded_owned);

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

	/* Once given a key, the checker requires one until the application
	 * takes it back outside a verify. A callback that does so through its
	 * ctx (e.g. to "remember" a failed "kid" lookup) only removes the key:
	 * the tokens after this one would otherwise meet an unkeyed checker,
	 * and an unsigned one would verify (GHSA-mhc9-xvg5-qg29). */
	if (key != NULL)
		__cmd->c.key_required = 1;
	else if (!__cmd->c.verifying)
		__cmd->c.key_required = 0;
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
	/* @rfc{7797,3} "b64" says how the payload is encoded, which only
	 * jwt_builder_setb64() decides (for every signature alike): refuse it
	 * by name, or inside a nameless JSON object merged into the header. */
	if (__cmd != NULL && value != NULL) {
		jwt_json_auto_t *obj = NULL;
		int b64 = 0;

		if (value->name != NULL && value->name[0] != '\0') {
			b64 = !strcmp(value->name, "b64");
		} else if (value->type == JWT_VALUE_JSON &&
			   value->json_val != NULL) {
			obj = jwt_json_parse(value->json_val,
					     JWT_JSON_REJECT_DUPLICATES, NULL);
			b64 = jwt_json_is_object(obj) &&
			      jwt_json_obj_get(obj, "b64") != NULL;
		}

		if (b64) {
			jwt_write_error(__cmd, "\"b64\" cannot be set as a "
					"header: use jwt_builder_setb64()");
			return value->error = JWT_VALUE_ERR_INVALID;
		}
	}

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
/* @rfc{7515,7.2.2} A keyring checker verifies a Compact token as the
 * equivalent one-signature Flattened JWS JSON Serialization, so it gets exactly
 * what a JSON token gets: a "kid" selects that ring key (no fallback), a
 * kid-less token is tried against every compatible key, each under the
 * alg/key-type binding and the key's "alg" pin; the typ/alg policy,
 * per-signature callback, claims, required claims and jti all apply; and
 * "none" is never accepted. The Compact path below only knows the single key,
 * which jwt_checker_setkeyring() clears, so it would treat the checker as
 * unkeyed and accept a forged unsigned token (GHSA-mhc9-xvg5-qg29).
 *
 * "protected" is the text before the FIRST '.', "signature" the text after the
 * LAST '.', and "payload" everything between, so an @rfc{7797} unencoded
 * payload containing '.' stays intact. The JSON is built with the JSON API,
 * never by formatting a string: a raw payload may hold quotes or backslashes
 * and must not be able to add members. Returns a malloc'd string, or NULL with
 * the checker error set. */
static char *compact_to_flattened(jwt_checker_t *checker, const char *token)
{
	static const char * const names[] = {
		"protected", "payload", "signature",
	};
	jwt_json_auto_t *root = NULL;
	char_auto *buf = NULL;
	const char *parts[ARRAY_SIZE(names)];
	char *first, *last, *out;
	size_t i, len = strlen(token) + 1;

	buf = jwt_malloc(len);
	if (buf == NULL) {
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}
	memcpy(buf, token, len);

	first = strchr(buf, '.');
	last = strrchr(buf, '.');
	if (first == NULL || first == last) {
		jwt_write_error(checker, "Invalid JWS Compact Serialization");
		return NULL;
	}
	*first = '\0';
	*last = '\0';
	parts[0] = buf;
	parts[1] = first + 1;
	parts[2] = last + 1;

	root = jwt_json_create();
	if (root == NULL) {
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		jwt_json_t *v = jwt_json_create_str(parts[i]);

		/* Jansson refuses a string that is not valid UTF-8 (json-c
		 * takes any bytes), e.g. a binary unencoded payload. */
		if (v == NULL) {
			jwt_write_error(checker, "Token is not valid UTF-8");
			return NULL;
		}
		/* obj_set consumes @v even when it fails. */
		if (jwt_json_obj_set(root, names[i], v)) {
			jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
			return NULL; // LCOV_EXCL_LINE
		}
	}

	out = jwt_json_serialize(root, JWT_JSON_COMPACT);
	if (out == NULL)
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE

	return out;
}

static int __verify(jwt_common_t *__cmd, const char *token)
{
	JWT_CONFIG_DECLARE(config);
	unsigned int payload_len;
	jwt_auto_t *jwt = NULL;
	int keyed, had_cb;

	/* Report only this call (checker reuse): jwt_write_error() keeps the
	 * first message, so a prior verify's error would mask this one's, and
	 * its signatures must not be reported for this one either. */
	FUNC(error_clear)(__cmd);
	{
		struct jwt_signature *s, *tmp;

		list_for_each_entry_safe(s, tmp, &__cmd->c.signatures, node) {
			list_del(&s->node);
			jwt_signature_free(s);
		}
		__cmd->c.n_signatures = 0;
		__cmd->c.last_sig_count = 0;

		/* @rfc{7515,4.1.3} Drop a confirmed embedded key from a prior
		 * verify before it can be borrowed by this one. */
		if (__cmd->c.embedded_owned != NULL) {
			jwks_free(__cmd->c.embedded_owned);
			__cmd->c.embedded_owned = NULL;
		}
	}

	if (token == NULL || !strlen(token)) {
		jwt_write_error(__cmd, "Must pass a token");
		return 1;
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

	/* A keyring checker verifies a Compact token as its one-signature JSON
	 * equivalent (see compact_to_flattened()), never on the single-key path
	 * below. Embedded-JWK verify keeps its own Compact flow and, as before,
	 * takes precedence over a keyring. */
	if (__cmd->c.keyring != NULL && !__cmd->c.embedded_jwk) {
		char_auto *flat = compact_to_flattened(__cmd, token);

		if (flat == NULL)
			return 1;

		return jwt_verify_json(__cmd, flat);
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

	/* @rfc{7515,4.1.3} Embedded-JWK verify: seed the key from the protected
	 * header "jwk", but only after confirming it against the pinned
	 * thumbprint or the allowlist. The callback (below) still sees and may
	 * override it. The owning keyring lives on the checker (freed next verify
	 * or at checker free) so jwt_checker_sig_key() can borrow the key. */
	if (__cmd->c.embedded_jwk) {
		const jwk_item_t *ek = NULL;

		__cmd->c.embedded_owned =
			jwt_embedded_jwk_key(&__cmd->c, jwt->headers, &ek);
		if (ek == NULL) {
			jwt_write_error(__cmd,
				"Embedded JWK is missing or not confirmed");
			return 1;
		}
		config.key = ek;
		config.alg = jwt->alg;
	}

	/* Noted before the callback runs, since it can reconfigure this very
	 * checker through its ctx (jwt_checker_setkey(), _setkeyring(),
	 * _setcb()). */
	keyed = config.key != NULL;
	had_cb = __cmd->c.cb != NULL;

	/* Let the user handle this and update config */
        if (__cmd->c.cb && __cmd->c.cb(jwt, &config)) {
		jwt_write_error(__cmd, "User callback returned error");
		return 1;
	}

	/* A checker given a key (jwt_checker_setkey(), or a header key confirmed
	 * for embedded-JWK verify) always verifies with one: the callback may
	 * replace the key, never remove it. config.alg can be JWT_ALG_NONE here
	 * (setkey() with JWT_ALG_NONE takes the key's "alg"; embedded-JWK takes
	 * the token's own), and with no key as well, the checks below would treat
	 * the checker as unkeyed and accept an unsigned ("alg":"none") token,
	 * e.g. when a "kid" lookup in the callback finds nothing
	 * (GHSA-mhc9-xvg5-qg29). The same holds if the callback gave the checker
	 * a key or keyring of its own while leaving this token without one, and
	 * if a callback (this one or an earlier verify's) has since removed the
	 * key the checker was given: see FUNC(setkey). */
	if ((keyed || __cmd->c.key != NULL || __cmd->c.keyring != NULL ||
	     __cmd->c.embedded_jwk || __cmd->c.key_required) &&
	    config.key == NULL) {
		/* With no verify callback, only a callback's earlier removal of
		 * the key (see FUNC(setkey)) gets here. */
		jwt_write_error(__cmd, "%s", had_cb ?
				"Callback left no verification key" :
				"A callback removed the checker's key");
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

int FUNC(verify)(jwt_common_t *__cmd, const char *token)
{
	int ret;

	if (__cmd == NULL)
		return 1;

	/* Not from this checker's own callbacks: the token being verified
	 * still uses the signatures and embedded key a new verify frees. */
	if (__cmd->c.verifying) {
		jwt_write_error(__cmd, "Checker is already verifying a token");
		return 1;
	}

	/* Its callbacks run inside; see FUNC(setkey). */
	__cmd->c.verifying++;
	ret = __verify(__cmd, token);
	__cmd->c.verifying--;

	return ret;
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
	checker->c.key_required = 1;

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

int jwt_checker_require(jwt_checker_t *checker, const char **claims,
			unsigned int count)
{
	char **copy = NULL;
	unsigned int i;

	if (checker == NULL)
		return 1;

	if (claims != NULL && count > 0) {
		for (i = 0; i < count; i++) {
			if (claims[i] == NULL || claims[i][0] == '\0') {
				jwt_write_error(checker,
					"A required claim name is empty");
				return 1;
			}
		}

		copy = jwt_malloc(count * sizeof(char *));
		if (copy == NULL) {
			jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}

		for (i = 0; i < count; i++) {
			size_t len = strlen(claims[i]) + 1;

			copy[i] = jwt_malloc(len);
			if (copy[i] == NULL) {
				// LCOV_EXCL_START
				while (i-- > 0)
					jwt_freemem(copy[i]);
				jwt_freemem(copy);
				jwt_write_error(checker, "Error allocating memory");
				return 1;
				// LCOV_EXCL_STOP
			}
			memcpy(copy[i], claims[i], len);
		}
	}

	/* Replace any previous requirement set. */
	if (checker->c.require != NULL) {
		for (i = 0; i < checker->c.n_require; i++)
			jwt_freemem(checker->c.require[i]);
		jwt_freemem(checker->c.require);
	}
	checker->c.require = copy;
	checker->c.n_require = copy ? count : 0;

	return 0;
}

/* Reject an out-of-range thumbprint selector at configure time (jwks_item_thumbprint
 * also rejects it later, but failing here gives a clearer error). */
static int thumbprint_alg_ok(jwt_checker_t *checker, jwk_thumbprint_alg_t alg)
{
	if (alg != JWK_THUMBPRINT_SHA256 && alg != JWK_THUMBPRINT_SHA384 &&
	    alg != JWK_THUMBPRINT_SHA512) {
		jwt_write_error(checker, "Invalid thumbprint algorithm");
		return 0;
	}
	return 1;
}

int jwt_checker_enable_embedded_jwk(jwt_checker_t *checker,
				    jwk_thumbprint_alg_t alg,
				    const char *expected_jkt)
{
	char *copy;
	size_t n;

	if (checker == NULL)
		return 1;

	if (!thumbprint_alg_ok(checker, alg))
		return 1;

	/* @rfc{7515,4.1.3} The header "jwk" is attacker-supplied, so a key
	 * confirmation is mandatory: refuse to enable a "trust whatever is
	 * embedded" mode. */
	if (expected_jkt == NULL || expected_jkt[0] == '\0') {
		jwt_write_error(checker,
			"A pinned thumbprint is required to trust an embedded JWK");
		return 1;
	}

	n = strlen(expected_jkt) + 1;
	copy = jwt_malloc(n);
	if (copy == NULL) {
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}
	memcpy(copy, expected_jkt, n);

	jwt_freemem(checker->c.embedded_jkt);
	checker->c.embedded_jkt = copy;
	checker->c.embedded_keyring = NULL;
	checker->c.embedded_alg = alg;
	checker->c.embedded_jwk = 1;

	return 0;
}

int jwt_checker_enable_embedded_jwk_keyring(jwt_checker_t *checker,
					    jwk_thumbprint_alg_t alg,
					    const jwk_set_t *allowed)
{
	if (checker == NULL)
		return 1;

	if (!thumbprint_alg_ok(checker, alg))
		return 1;

	if (allowed == NULL) {
		jwt_write_error(checker,
			"An allowlist keyring is required to trust an embedded JWK");
		return 1;
	}

	/* The keyring is borrowed (like the verify keyring); the caller keeps
	 * ownership and must keep it valid for the checker's lifetime. */
	jwt_freemem(checker->c.embedded_jkt);
	checker->c.embedded_jkt = NULL;
	checker->c.embedded_keyring = allowed;
	checker->c.embedded_alg = alg;
	checker->c.embedded_jwk = 1;

	return 0;
}

static const struct jwt_signature *checker_sig_at(const jwt_checker_t *checker,
						  unsigned int index)
{
	const struct jwt_signature *s;
	unsigned int i = 0;

	/* Only the last call's signatures: an early failure (e.g. in
	 * jwt_checker_verify_detached()) resets the count, not the list. */
	if (checker == NULL || checker->c.signatures.next == NULL ||
	    index >= checker->c.last_sig_count)
		return NULL;

	list_for_each_entry(s, &checker->c.signatures, node) {
		if (i++ == index)
			return s;
	}

	/* Only if recording the Compact path's signature failed. */
	return NULL; // LCOV_EXCL_LINE
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

	/* @rfc{7797,3} "b64" is jwt_builder_setb64()'s alone (header_set
	 * refuses it), but the callback can still set one with
	 * jwt_header_set(). Refuse one that disagrees with the setting: the
	 * token would claim an encoding its payload does not have, and a JWT
	 * would slip past the b64=false guard below. */
	{
		jwt_json_t *jb = jwt_json_obj_get(jwt->headers, "b64");

		if (jb != NULL && (!jwt_json_is_bool(jb) ||
		    (jwt_json_is_true(jb) ? 1 : 0) != jwt->b64)) {
			jwt_write_error(__cmd, "A \"b64\" header must match "
					"jwt_builder_setb64()");
			return NULL;
		}
	}

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
