/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
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

static jwt_json_t *jwt_base64uri_decode_to_json(char *src)
{
	jwt_json_t *js;
	char *buf;
	int len;

	buf = jwt_base64uri_decode(src, &len);

	if (buf == NULL)
		return NULL; // LCOV_EXCL_LINE

	buf[len] = '\0';

	/* @rfc{8725,2.4} Reject duplicate members in the token header/payload so
	 * a peer that selects a different occurrence cannot be made to disagree
	 * with us about a claim/header. Supported by the Jansson backend; json-c
	 * cannot reject duplicates (it keeps the last), a documented limitation. */
	js = jwt_json_parse(buf, JWT_JSON_REJECT_DUPLICATES, NULL);

	jwt_freemem(buf);

	return js;
}

static int jwt_parse_payload(jwt_t *jwt, char *payload)
{
	if (jwt->claims)
		jwt_json_releasep(&(jwt->claims));

	jwt->claims = jwt_base64uri_decode_to_json(payload);
	if (!jwt->claims) {
		jwt_write_error(jwt, "Error parsing payload");
		return 1;
	}

	return 0;
}

static int jwt_parse_head(jwt_t *jwt, char *head)
{
	jwt_json_t *jalg;

	if (jwt->headers)
		jwt_json_releasep(&(jwt->headers));

	jwt->headers = jwt_base64uri_decode_to_json(head);
	if (!jwt->headers) {
		jwt_write_error(jwt, "Error parsing header");
		return 1;
	}

	jwt->alg = JWT_ALG_NONE;

	jalg = jwt_json_obj_get(jwt->headers, "alg");
	if (jalg && jwt_json_is_string(jalg)) {
		const char *alg = jwt_json_str_val(jalg);

		jwt->alg = jwt_str_alg(alg);

		if (jwt->alg >= JWT_ALG_INVAL) {
			jwt_write_error(jwt, "Invalid ALG: [%s]", alg);
			return 1;
		}

		return 0;
	}

	jwt_write_error(jwt, "Missing or invalid \"alg\" header");

	return 1;
}

/* @rfc{7515,4.1.11} Process the "crit" (Critical) header parameter.
 *
 * If present, "crit" must be a non-empty array of strings. Each string
 * names a header parameter that must (a) actually be present in the header
 * and (b) be understood by the recipient. LibJWT understands no extension
 * header parameters on its own, so the application must declare the ones it
 * handles via jwt_checker_understands() (passed in as @understood, a
 * NULL-terminated list which may itself be NULL). Any listed parameter not
 * in that list makes the JWS invalid.
 */
int jwt_check_crit(jwt_t *jwt, char * const *understood)
{
	jwt_json_t *crit, *ent;
	size_t i;

	crit = jwt_json_obj_get(jwt->headers, "crit");
	if (crit == NULL)
		return 0;

	if (!jwt_json_is_array(crit)) {
		jwt_write_error(jwt, "\"crit\" header must be an array");
		return 1;
	}

	if (jwt_json_arr_size(crit) == 0) {
		jwt_write_error(jwt, "\"crit\" header must not be empty");
		return 1;
	}

	jwt_json_arr_foreach(crit, i, ent) {
		const char *name;
		int found = 0;

		if (!jwt_json_is_string(ent)) {
			jwt_write_error(jwt,
				"\"crit\" header entries must be strings");
			return 1;
		}

		name = jwt_json_str_val(ent);

		/* Must actually appear in the header. */
		if (jwt_json_obj_get(jwt->headers, name) == NULL) {
			jwt_write_error(jwt,
				"\"crit\" lists \"%s\" which is not in the header",
				name);
			return 1;
		}

		/* Must be understood by the application. */
		if (understood) {
			size_t j;

			for (j = 0; understood[j] != NULL; j++) {
				if (!strcmp(understood[j], name)) {
					found = 1;
					break;
				}
			}
		}

		if (!found) {
			jwt_write_error(jwt,
				"Unsupported critical header: \"%s\"", name);
			return 1;
		}
	}

	return 0;
}

int jwt_parse(jwt_t *jwt, const char *token, unsigned int *len)
{
	char_auto *head = NULL;
	char *payload, *sig;
	int head_len = strlen(token) + 1;

	head = jwt_malloc(head_len);
	if (!head) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* head_len includes nil */
	memcpy(head, token, head_len);

	/* Find the components. */
	for (payload = head; payload[0] != '.'; payload++) {
		if (payload[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of header");
			return 1;
		}
	}

	payload[0] = '\0';
	payload++;

	for (sig = payload; sig[0] != '.'; sig++) {
		if (sig[0] == '\0') {
			jwt_write_error(jwt,
				"No dot found looking for end of payload");
			return 1;
		}
	}

	sig[0] = '\0';

	/* Now that we have everything split up, let's check out the
	 * header. */
	if (jwt_parse_head(jwt, head))
		return 1;

	if (jwt_parse_payload(jwt, payload))
		return 1;

	*len = sig - head;

	return 0;
}

/* @rfc{7519,4.1.3} "aud" may be a single string OR an array of strings. Return
 * 1 if the expected audience is among the array elements, 0 otherwise. */
static int __aud_matches_array(jwt_t *jwt, const char *want)
{
	jwt_json_t *aud, *ent;
	size_t i, n;

	aud = jwt_json_obj_get(jwt->claims, "aud");
	if (aud == NULL || !jwt_json_is_array(aud))
		return 0;

	n = jwt_json_arr_size(aud);
	for (i = 0; i < n; i++) {
		ent = jwt_json_arr_get(aud, i);
		if (ent && jwt_json_is_string(ent) &&
		    !strcmp(want, jwt_json_str_val(ent)))
			return 1;
	}

	return 0;
}

static int __check_str_claim(jwt_t *jwt, jwt_claims_t claim, char *claim_str)
{
	jwt_checker_t *checker = jwt->checker;
	jwt_value_t jval;
	const char *str;
	jwt_value_error_t err;

	if (!(checker->c.claims & claim))
		return 0;

	str = jwt_checker_claim_get(checker, claim);
	if (str == NULL)
		return 1; // LCOV_EXCL_LINE
			  // Check above makes this nearly impossible to hit

	jwt_set_GET_STR(&jval, claim_str);
	err = jwt_claim_get(jwt, &jval);

	if (err == JWT_VALUE_ERR_NONE)
		return strcmp(str, jval.str_val) ? 1 : 0;

	/* A type error on "aud" means it is an array (RFC 7519 4.1.3 allows
	 * that): accept the token if the expected audience is among the
	 * elements. Any other claim, or a non-matching array, fails. */
	if (claim == JWT_CLAIM_AUD && err == JWT_VALUE_ERR_TYPE &&
	    __aud_matches_array(jwt, str))
		return 0;

	return 1;
}

static jwt_claims_t __verify_claims(jwt_t *jwt)
{
	jwt_checker_t *checker = jwt->checker;
	jwt_value_t jval;
	time_t now = time(NULL);
	jwt_value_error_t err;
	jwt_claims_t failed = 0;

	/* expiration in past */
	if (checker->c.claims & JWT_CLAIM_EXP) {
		jwt_set_GET_INT(&jval, "exp");
		err = jwt_claim_get(jwt, &jval);

		if (err == JWT_VALUE_ERR_NONE) {
			if (jval.int_val <= (now - checker->c.exp)) {
				failed |= JWT_CLAIM_EXP;
			}
		} else if (err != JWT_VALUE_ERR_NOEXIST)
			failed |= JWT_CLAIM_EXP; // LCOV_EXCL_LINE
	}

	/* not valid before now */
	if (checker->c.claims & JWT_CLAIM_NBF) {
		jwt_set_GET_INT(&jval, "nbf");
		err = jwt_claim_get(jwt, &jval);

		if (err == JWT_VALUE_ERR_NONE) {
			if (jval.int_val > (now + checker->c.nbf)) {
				failed |= JWT_CLAIM_NBF;
			}
		} else if (err != JWT_VALUE_ERR_NOEXIST)
			failed |= JWT_CLAIM_NBF; // LCOV_EXCL_LINE
	}

	/* issuer doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_ISS, "iss"))
		failed |= JWT_CLAIM_ISS;

	/* subject doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_SUB, "sub"))
		failed |= JWT_CLAIM_SUB;

	/* audience doesn't match */
	if (__check_str_claim(jwt, JWT_CLAIM_AUD, "aud"))
		failed |= JWT_CLAIM_AUD;

	return failed;
}

/* @rfc{7519,4.1.7} jti: hand the id to the application callback, which
 * validates/consumes it (e.g. replay protection). A registered callback means
 * a token with no jti is rejected.
 *
 * This is intentionally kept separate from __verify_claims() and run only
 * after the signature has verified: the callback typically mutates external
 * state (records/burns the jti for replay protection), so it must not fire on
 * a token whose signature has not been validated. Running it pre-signature
 * would let an attacker who knows a victim's jti poison the replay cache or
 * burn the id with forged, unauthenticated tokens. */
static jwt_claims_t __verify_jti(jwt_t *jwt)
{
	jwt_checker_t *checker = jwt->checker;
	jwt_value_t jval;
	jwt_value_error_t err;

	if (!checker->c.jti_check)
		return 0;

	JWT_CONFIG_DECLARE(jti_config);

	jwt_set_GET_STR(&jval, "jti");
	err = jwt_claim_get(jwt, &jval);

	if (err != JWT_VALUE_ERR_NONE)
		return JWT_CLAIM_JTI;

	jti_config.ctx = checker->c.jti_ctx;
	if (checker->c.jti_check(jwt, &jti_config, jval.str_val))
		return JWT_CLAIM_JTI;

	return 0;
}

/* This is after parsing and possibly a user callback. */
static int __verify_config_post(jwt_t *jwt, const jwt_config_t *config,
				unsigned int sig_len)
{
	/* Yes, we do this before checking a signature. */
	if (__verify_claims(jwt)) {
		/* TODO Pass back the ORd list of claims failed. */
		jwt_write_error(jwt, "Failed one or more claims");
		return 1;
	}

	if (!sig_len) {
		if (config->key || config->alg != JWT_ALG_NONE ||
		    jwt->alg != JWT_ALG_NONE) {
			jwt_write_error(jwt,
				"Expected a signature, but JWT has none");
			return 1;
		}

		return 0;
	}

	/* Signature is known to be present from this point */
	if (jwt->alg == JWT_ALG_NONE) {
		jwt_write_error(jwt, "JWT has signature block, but no alg set");
		return 1;
	}

	if (config->key == NULL) {
		jwt_write_error(jwt,
			"JWT has signature, but no key was given");
		return 1;
	}

	/* Key is known to be given at this point */
	if (config->alg == JWT_ALG_NONE) {
		if (config->key->alg != jwt->alg) {
			jwt_write_error(jwt, "Key alg does not match JWT");
			return 1;
		}
	} else if (config->key->alg == JWT_ALG_NONE) {
		if (config->alg != jwt->alg) {
			jwt_write_error(jwt, "Config alg does not match JWT");
			return 1;
		}
	} else if (config->alg != config->key->alg) {
		/* It's not really possible to get here due to checks in setkey */
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Config and key alg does not match");
		return 1;
		// LCOV_EXCL_STOP
	}

	/* Algorithm is now bound (jwt->alg). Defensively confirm that the
	 * JWK's actual key type can carry it. This blocks algorithm
	 * confusion (GHSA-q843-6q5f-w55g) even if a malformed JWK has an
	 * "alg" hint that disagrees with its "kty". */
	if (jwt_alg_required_kty(jwt->alg) != config->key->kty) {
		jwt_write_error(jwt, "Key type does not match JWT alg");
		return 1;
	}

	return 0;
}

jwt_t *jwt_verify_complete(jwt_t *jwt, const jwt_config_t *config,
			   const char *token, unsigned int payload_len)
{
	const char *sig;
	unsigned int sig_len;

	sig = token + (payload_len + 1);
	sig_len = strlen(sig);

	/* Check for conflicts in user request and JWT, and run the read-only
	 * claim checks (exp/nbf/iss/sub/aud). */
	if (__verify_config_post(jwt, config, sig_len))
		return jwt;

	/* After all the checks, if we don't have a sig, we can move on. */
	if (sig_len) {
		/* At this point, config is never NULL */
		jwt->key = config->key;

		jwt = jwt_verify_sig(jwt, token, payload_len, sig);
		if (jwt->error)
			return jwt;
	}

	/* Signature has now verified (or there is none and "none" was
	 * permitted). Only now run the jti replay callback, which may mutate
	 * external state and must not fire on an unauthenticated token. */
	if (__verify_jti(jwt))
		jwt_write_error(jwt, "Failed one or more claims");

	return jwt;
}

/* ===================================================================
 * @rfc{7515,7.2} JWS JSON Serialization (multi-signature) verification
 * =================================================================== */

static char *jwt_str_dup(const char *s)
{
	size_t n;
	char *d;

	if (s == NULL)
		return NULL; // LCOV_EXCL_LINE

	n = strlen(s) + 1;
	d = jwt_malloc(n);
	if (d != NULL)
		memcpy(d, s, n);

	return d;
}

static const char *json_str(const jwt_json_t *obj, const char *key)
{
	jwt_json_t *v = jwt_json_obj_get(obj, key);

	return (v && jwt_json_is_string(v)) ? jwt_json_str_val(v) : NULL;
}

/* Parse one signature entry (a General-form array element, or the Flattened
 * top-level object) into a new jwt_signature appended to the checker's list:
 * its verbatim base64url "protected" and "signature", the decoded protected
 * header, its algorithm, and the optional unprotected "header". */
static int build_sig_entry(jwt_checker_t *checker, jwt_json_t *entry)
{
	jwt_json_t *prot_obj, *hdr_j, *hdr_clone = NULL;
	const char *prot_b64, *sig_b64, *alg_str;
	struct jwt_signature *s;
	jwt_alg_t alg;

	prot_b64 = json_str(entry, "protected");
	sig_b64 = json_str(entry, "signature");
	if (prot_b64 == NULL || sig_b64 == NULL) {
		jwt_write_error(checker,
			"JWS signature entry missing \"protected\"/\"signature\"");
		return 1;
	}

	prot_obj = jwt_base64uri_decode_to_json((char *)prot_b64);
	if (prot_obj == NULL || !jwt_json_is_object(prot_obj)) {
		jwt_json_release(prot_obj);
		jwt_write_error(checker, "JWS protected header is not valid JSON");
		return 1;
	}

	/* @rfc{8725,3.1} Bind the algorithm to this entry's protected header.
	 * "none" is never accepted in a JSON-serialized JWS. */
	alg_str = json_str(prot_obj, "alg");
	alg = alg_str ? jwt_str_alg(alg_str) : JWT_ALG_INVAL;
	if (alg == JWT_ALG_NONE || alg >= JWT_ALG_INVAL) {
		jwt_json_release(prot_obj);
		jwt_write_error(checker, "JWS signature has an invalid \"alg\"");
		return 1;
	}

	hdr_j = jwt_json_obj_get(entry, "header");
	if (hdr_j != NULL) {
		if (!jwt_json_is_object(hdr_j) ||
		    jwt_header_params_overlap(prot_obj, hdr_j)) {
			jwt_json_release(prot_obj);
			jwt_write_error(checker,
				"JWS unprotected header is invalid or overlaps");
			return 1;
		}
		hdr_clone = jwt_json_clone(hdr_j);
		if (hdr_clone == NULL) {
			// LCOV_EXCL_START
			jwt_json_release(prot_obj);
			jwt_write_error(checker, "Error allocating memory");
			return 1;
			// LCOV_EXCL_STOP
		}
	}

	s = jwt_signature_append(&checker->c);
	if (s == NULL) {
		// LCOV_EXCL_START
		jwt_json_release(prot_obj);
		jwt_json_release(hdr_clone);
		jwt_write_error(checker, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	s->alg = alg;
	s->protected = prot_obj;
	s->header = hdr_clone;
	s->protected_b64 = jwt_str_dup(prot_b64);
	s->sig_b64 = jwt_str_dup(sig_b64);
	if (s->protected_b64 == NULL || s->sig_b64 == NULL) {
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	return 0;
}

/* Try one candidate key against signature @s over @input. Applies the
 * algorithm/key-type anti-confusion gate (GHSA-q843-6q5f-w55g) before any
 * verify, and routes the crypto to the key's origin backend via jwt_item_ops()
 * inside jwt_verify_sig(). Sets s->verified/s->key on success. */
static void try_candidate(jwt_t *jwt, struct jwt_signature *s,
			  const jwk_item_t *key, const char *input,
			  unsigned int input_len)
{
	if (key == NULL || s->verified)
		return;

	if (jwt_alg_required_kty(s->alg) != jwks_item_kty(key))
		return;

	jwt->alg = s->alg;
	jwt->key = key;
	jwt->error = 0;
	jwt->error_msg[0] = '\0';

	jwt_verify_sig(jwt, input, input_len, s->sig_b64);

	if (!jwt->error) {
		s->verified = 1;
		s->key = key;
	}

	/* Don't let a failed attempt's error leak into the checker result. */
	jwt->error = 0;
	jwt->error_msg[0] = '\0';
}

/* Verify one signature entry: run the optional per-signature callback, select
 * the key (the checker's single key, a "kid"-named keyring key, or every
 * compatible keyring key), and verify. */
static int verify_entry(jwt_checker_t *checker, jwt_t *jwt,
			struct jwt_signature *s, const char *payload_b64,
			int payload_len)
{
	JWT_CONFIG_DECLARE(config);
	const jwk_set_t *ring = checker->c.keyring;
	char_auto *input = NULL;
	const char *kid;
	int prot_len, scan;

	/* @rfc{7515,5.1} Signing input is the VERBATIM protected_b64 "." payload_b64. */
	prot_len = (int)strlen(s->protected_b64);
	input = jwt_malloc((size_t)prot_len + payload_len + 2);
	if (input == NULL)
		return 1; // LCOV_EXCL_LINE
	sprintf(input, "%s.%s", s->protected_b64, payload_b64);

	/* This signature's header drives crit/callback. */
	jwt->headers = s->protected;
	jwt->alg = s->alg;

	if (jwt_check_crit(jwt, checker->c.understood)) {
		jwt_copy_error(checker, jwt);
		jwt->headers = NULL;
		return 1;
	}

	/* Seed the candidate: a kid-named keyring key (a binding assertion, no
	 * fallback), or the checker's single key. A keyless keyring entry scans. */
	kid = json_str(s->protected, "kid");
	if (ring != NULL) {
		config.key = (kid != NULL)
			? jwks_find_bykid((jwk_set_t *)ring, kid) : NULL;
		scan = (kid == NULL);
	} else {
		config.key = checker->c.key;
		scan = 0;
	}
	config.alg = s->alg;
	config.ctx = checker->c.cb_ctx;

	if (checker->c.cb && checker->c.cb(jwt, &config)) {
		/* Callback rejected this signature; not a hard error under ANY. */
		jwt->headers = NULL;
		return 0;
	}

	if (config.key != NULL) {
		/* Explicit key (kid match, single key, or callback override). */
		try_candidate(jwt, s, config.key, input, (unsigned int)strlen(input));
	} else if (scan) {
		size_t i, n = jwks_item_count(ring);

		for (i = 0; i < n && !s->verified; i++) {
			const jwk_item_t *k = jwks_item_get(ring, i);
			jwt_alg_t kalg = jwks_item_alg(k);

			if (kalg != JWT_ALG_NONE && kalg != s->alg)
				continue;
			try_candidate(jwt, s, k, input, (unsigned int)strlen(input));
		}
	}

	jwt->headers = NULL;

	return 0;
}

int jwt_verify_json(jwt_checker_t *checker, const char *token)
{
	jwt_json_auto_t *root = NULL;
	jwt_json_t *payload_j, *sigs;
	jwt_auto_t *jwt = NULL;
	const char *payload_b64;
	struct jwt_signature *s;
	int n_verified = 0, sig_ok, payload_len;
	size_t n_entries;

	/* Reset for a reused checker. */
	checker->error = 0;
	checker->error_msg[0] = '\0';
	checker->c.last_sig_count = 0;

	root = jwt_json_parse(token, JWT_JSON_REJECT_DUPLICATES, NULL);
	if (root == NULL || !jwt_json_is_object(root)) {
		jwt_write_error(checker, "Invalid JWS JSON Serialization");
		return 1;
	}

	payload_j = jwt_json_obj_get(root, "payload");
	if (payload_j == NULL || !jwt_json_is_string(payload_j)) {
		jwt_write_error(checker,
			"JWS JSON Serialization missing a \"payload\"");
		return 1;
	}
	payload_b64 = jwt_json_str_val(payload_j);
	payload_len = (int)strlen(payload_b64);

	/* @rfc{7515,7.2} General has a "signatures" array; Flattened hoists a
	 * single signature's members to the top level. They are exclusive. */
	sigs = jwt_json_obj_get(root, "signatures");
	if (sigs != NULL) {
		size_t i, cnt;

		if (jwt_json_obj_get(root, "protected") ||
		    jwt_json_obj_get(root, "signature") ||
		    jwt_json_obj_get(root, "header")) {
			jwt_write_error(checker,
				"JWS JSON mixes General and Flattened members");
			return 1;
		}
		if (!jwt_json_is_array(sigs)) {
			jwt_write_error(checker,
				"\"signatures\" must be an array");
			return 1;
		}
		cnt = jwt_json_arr_size(sigs);
		if (cnt == 0) {
			jwt_write_error(checker,
				"\"signatures\" must not be empty");
			return 1;
		}
		for (i = 0; i < cnt; i++) {
			if (build_sig_entry(checker, jwt_json_arr_get(sigs, i)))
				return 1;
		}
	} else if (build_sig_entry(checker, root)) {
		return 1;
	}

	n_entries = checker->c.n_signatures;
	checker->c.last_sig_count = (unsigned int)n_entries;

	if (checker->c.key == NULL && checker->c.keyring == NULL) {
		jwt_write_error(checker, "No key or keyring set");
		return 1;
	}

	/* A transient JWT carrying the shared payload for the per-signature
	 * verify and the read-only claim checks. */
	jwt = jwt_new();
	if (jwt == NULL) {
		jwt_write_error(checker, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}
	jwt->checker = checker;
	jwt_json_releasep(&jwt->claims);
	/* Release the empty header object jwt_new() allocated: from here on
	 * jwt->headers only ever borrows each signature's protected header. */
	jwt_json_releasep(&jwt->headers);
	jwt->claims = jwt_base64uri_decode_to_json((char *)payload_b64);
	if (jwt->claims == NULL) {
		jwt_write_error(checker, "Error parsing payload");
		return 1;
	}

	list_for_each_entry(s, &checker->c.signatures, node) {
		if (verify_entry(checker, jwt, s, payload_b64, payload_len)) {
			jwt->headers = NULL;
			return 1;
		}
		if (s->verified)
			n_verified++;
	}
	jwt->headers = NULL;

	/* @rfc{7515,7.2} Policy: ANY accepts on the first verified signature;
	 * ALL requires every signature in the token to verify. */
	if (checker->c.policy == JWT_VERIFY_POLICY_ALL)
		sig_ok = (n_verified == (int)n_entries);
	else
		sig_ok = (n_verified >= 1);

	if (!sig_ok) {
		jwt_write_error(checker,
			"Signature policy not met (%d of %zu verified)",
			n_verified, n_entries);
	} else if (__verify_claims(jwt)) {
		jwt_write_error(checker, "Failed one or more claims");
	} else if (__verify_jti(jwt)) {
		/* jti runs only after signature + claims succeed. */
		jwt_write_error(checker, "Failed one or more claims");
	}

	return checker->error;
}
