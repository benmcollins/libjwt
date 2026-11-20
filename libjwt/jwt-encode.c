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

static int write_js(const jwt_json_t *js, char **buf)
{
	*buf = jwt_json_serialize(js, JWT_JSON_SORT_KEYS | JWT_JSON_COMPACT);

	return *buf == NULL ? 1 : 0;
}

/* @rfc{7515,7.2} JWS signature list helpers, mirroring the jwe_recipient ones.
 * The list lives on jwt_common; a Compact/Flattened JWS is a one-element list,
 * General is N. */
struct jwt_signature *jwt_signature_first(struct jwt_common *cmd)
{
	if (cmd == NULL || cmd->signatures.next == &cmd->signatures)
		return NULL;

	return list_first_entry(&cmd->signatures, struct jwt_signature, node);
}

static struct jwt_signature *signature_new(struct jwt_common *cmd, int first)
{
	struct jwt_signature *s;

	if (cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	s = jwt_malloc(sizeof(*s));
	if (s == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(s, 0, sizeof(*s));
	if (first)
		list_add(&s->node, &cmd->signatures);
	else
		list_add_tail(&s->node, &cmd->signatures);
	cmd->n_signatures++;

	return s;
}

struct jwt_signature *jwt_signature_append(struct jwt_common *cmd)
{
	return signature_new(cmd, 0);
}

/* The jwt_builder_setkey() signer goes first in the list. */
struct jwt_signature *jwt_signature_prepend(struct jwt_common *cmd)
{
	return signature_new(cmd, 1);
}

/* Free one signature and the members it owns. Does not unlink it; the caller
 * (FUNC(free)) drains the whole list. */
void jwt_signature_free(struct jwt_signature *s)
{
	if (s == NULL)
		return; // LCOV_EXCL_LINE

	jwt_json_release(s->protected);
	jwt_json_release(s->header);
	jwt_freemem(s->protected_b64);
	jwt_freemem(s->sig_b64);
	jwt_freemem(s);
}

/* Parse @value_json and set it under @key on @obj (created on first use).
 * Rejects a NULL arg, the library-managed "alg" and "b64", a parse failure,
 * and a duplicate key. Used by both per-signature header setters. */
static int signature_set_header(jwt_json_t **obj, const char *key,
				const char *value_json)
{
	jwt_json_t *val;

	if (key == NULL || value_json == NULL)
		return 1;

	/* "alg" is set by the library from the signer's algorithm, and
	 * @rfc{7797,3} "b64" from jwt_builder_setb64(): it describes the shared
	 * payload, so it MUST be the same in every signature. */
	if (!strcmp(key, "alg") || !strcmp(key, "b64"))
		return 1;

	if (*obj == NULL) {
		*obj = jwt_json_create();
		if (*obj == NULL)
			return 1; // LCOV_EXCL_LINE
	}

	if (jwt_json_obj_has(*obj, key))
		return 1;

	val = jwt_json_parse(value_json, JWT_JSON_DECODE_ANY, NULL);
	if (val == NULL)
		return 1;

	/* obj_set steals the reference to val on success and on failure. */
	if (jwt_json_obj_set(*obj, key, val))
		return 1; // LCOV_EXCL_LINE

	return 0;
}

int jwt_signature_add_protected_json(jwt_signature_t *signature,
				     const char *key, const char *value_json)
{
	if (signature == NULL)
		return 1;

	return signature_set_header(&signature->protected, key, value_json);
}

int jwt_signature_add_header_json(jwt_signature_t *signature,
				  const char *key, const char *value_json)
{
	if (signature == NULL)
		return 1;

	/* @rfc{7515,4.1.11} "crit" MUST be integrity protected, so never in
	 * the unprotected header (jwt_checker_verify() rejects it there). */
	if (key != NULL && !strcmp(key, "crit"))
		return 1;

	return signature_set_header(&signature->header, key, value_json);
}

/* @rfc{7515,7.2.1} A header parameter must not appear in both a signature's
 * protected and unprotected header. obj_foreach stops (returns non-zero) at the
 * first member of @header that is also present in @protected, even as a JSON
 * null (see jwt_json_obj_has()). */
static int overlap_cb(const char *key, jwt_json_t *value, void *ctx)
{
	(void)value;
	return jwt_json_obj_has((const jwt_json_t *)ctx, key);
}

int jwt_header_params_overlap(const jwt_json_t *protected,
			      const jwt_json_t *header)
{
	return jwt_json_obj_foreach(header, overlap_cb, (void *)protected);
}

/* Set "protected"/"header"/"signature" members on @target (a General-form array
 * element or the Flattened top-level object). The unprotected @header is cloned
 * (it is owned by the signature); the base64url strings are stolen by obj_set. */
static int fill_sig_json(jwt_json_t *target, const char *prot_b64,
			 const jwt_json_t *header, const char *sig_b64)
{
	jwt_json_t *v;

	v = jwt_json_create_str(prot_b64);
	if (v == NULL || jwt_json_obj_set(target, "protected", v))
		return 1; // LCOV_EXCL_LINE

	if (header) {
		v = jwt_json_clone(header);
		if (v == NULL || jwt_json_obj_set(target, "header", v))
			return 1; // LCOV_EXCL_LINE
	}

	v = jwt_json_create_str(sig_b64);
	if (v == NULL || jwt_json_obj_set(target, "signature", v))
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* Build one signature's protected header: the shared base header (@jwt->headers,
 * which already carries any "typ"/app members and "crit"), overlaid with this
 * signer's own protected members, with "alg" forced to the signer's algorithm
 * and a default "typ":"JWT" added when absent (matching the compact path). */
static jwt_json_t *build_protected(jwt_t *jwt, struct jwt_signature *s,
				   jwt_alg_t alg)
{
	jwt_json_t *prot, *v;

	prot = jwt_json_clone(jwt->headers);
	if (prot == NULL)
		return NULL; // LCOV_EXCL_LINE

	if (s->protected && jwt_json_obj_merge(prot, s->protected)) {
		// LCOV_EXCL_START
		jwt_json_release(prot);
		return NULL;
		// LCOV_EXCL_STOP
	}

	v = jwt_json_create_str(jwt_alg_str(alg));
	if (v == NULL || jwt_json_obj_set(prot, "alg", v)) {
		jwt_json_release(prot); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	/* An application's "typ", a JSON null one too, is kept. */
	if (!jwt_json_obj_has(prot, "typ")) {
		v = jwt_json_create_str("JWT");
		if (v == NULL || jwt_json_obj_set(prot, "typ", v)) {
			jwt_json_release(prot); // LCOV_EXCL_LINE
			return NULL; // LCOV_EXCL_LINE
		}
	}

	return prot;
}

static int jwt_validate_crit(jwt_t *jwt, const jwt_json_t *hdr,
			     jwt_json_t *crit);

/* Whether @crit, a validated "crit" array, lists @name. */
static int crit_lists(const jwt_json_t *crit, const char *name)
{
	jwt_json_t *ent;
	size_t i;

	jwt_json_arr_foreach(crit, i, ent) {
		if (!strcmp(jwt_json_str_val(ent), name))
			return 1;
	}

	return 0;
}

/* @rfc{7515,4.1.11} A signature's own protected "crit" lists critical
 * parameters of its own, so check it against its protected header @prot as
 * the shared one was checked against the shared header. @prot carries the
 * shared header's critical parameters too ("b64" for an unencoded payload,
 * jwt_builder_setcrit() names), which build_protected() let this "crit"
 * replace: list them again, first, then this signature's others. Both lists
 * are valid and each name is listed once, so the union is valid as well. */
static int sig_crit_check(jwt_t *jwt, const struct jwt_signature *s,
			  jwt_json_t *prot)
{
	jwt_json_t *mine, *base, *crit, *ent, *v;
	size_t i;

	mine = s->protected ? jwt_json_obj_get(s->protected, "crit") : NULL;
	if (mine == NULL)
		return 0;	/* The shared "crit" is validated already. */

	if (jwt_validate_crit(jwt, prot, mine))
		return 1;

	base = jwt_json_obj_get(jwt->headers, "crit");
	if (base == NULL)
		return 0;	/* As merged, @prot's "crit" is @mine. */

	crit = jwt_json_clone(base);
	if (crit == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	jwt_json_arr_foreach(mine, i, ent) {
		if (crit_lists(base, jwt_json_str_val(ent)))
			continue;

		v = jwt_json_create_str(jwt_json_str_val(ent));
		if (v == NULL || jwt_json_arr_append(crit, v)) {
			// LCOV_EXCL_START
			jwt_json_release(crit);
			jwt_write_error(jwt, "Error allocating memory");
			return 1;
			// LCOV_EXCL_STOP
		}
	}

	/* obj_set steals @crit (on failure too) in place of @mine. */
	if (jwt_json_obj_set(prot, "crit", crit)) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error allocating memory");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

/* Sign one signature @s with @alg/@key and add it to the output: an element
 * of @sig_arr (General), or the top-level @out_obj (Flattened). @s supplies
 * the per-signature headers. @payload is the shared payload part. */
static int encode_one_sig(jwt_t *jwt, struct jwt_signature *s, jwt_alg_t alg,
			  const jwk_item_t *key, const char *payload,
			  size_t payload_len, jwt_json_t *out_obj,
			  jwt_json_t *sig_arr)
{
	jwt_json_auto_t *prot = NULL;
	char_auto *prot_b64 = NULL, *sig_b64 = NULL, *input = NULL;
	char *buf = NULL, *rawsig = NULL;
	unsigned int rawsig_len = 0;
	size_t input_len;
	int prot_len, enc;

	/* "none" is not allowed in a JSON JWS. An add_signature() signer
	 * always names its alg; FUNC(generate) resolved the setkey() signer's
	 * from its key (e.g. setkey(NONE, key)), so none is left only when
	 * there is no key at all. */
	if (alg == JWT_ALG_NONE) {
		jwt_write_error(jwt,
			"A JSON-serialized JWS cannot use \"none\"");
		return 1;
	}

	prot = build_protected(jwt, s, alg);
	if (prot == NULL)
		return 1; // LCOV_EXCL_LINE

	if (sig_crit_check(jwt, s, prot))
		return 1;

	if (s->header && jwt_header_params_overlap(prot, s->header)) {
		jwt_write_error(jwt,
			"protected and unprotected headers overlap");
		return 1;
	}

	if (write_js(prot, &buf))
		return 1; // LCOV_EXCL_LINE
	prot_len = jwt_base64uri_encode(&prot_b64, buf, (int)strlen(buf));
	jwt_freemem(buf);
	if (prot_len <= 0) {
		jwt_write_error(jwt, "Error encoding protected header"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}
	/* The return counts stripped '=' padding; use the true length. */
	prot_len = (int)strlen(prot_b64);

	/* @rfc{7797,3} Signing input: BASE64URL(protected) "." payload
	 * (payload is base64url or raw per b64; binary-safe). */
	input_len = (size_t)prot_len + 1 + payload_len;
	input = jwt_malloc(input_len + 1);
	if (input == NULL)
		return 1; // LCOV_EXCL_LINE
	memcpy(input, prot_b64, prot_len);
	input[prot_len] = '.';
	memcpy(input + prot_len + 1, payload, payload_len);
	input[input_len] = '\0';

	jwt->alg = alg;
	jwt->key = key;
	if (jwt_sign(jwt, &rawsig, &rawsig_len, input, input_len))
		return 1;

	enc = jwt_base64uri_encode(&sig_b64, rawsig, (int)rawsig_len);
	jwt_freemem(rawsig);
	if (enc <= 0) {
		jwt_write_error(jwt, "Error encoding signature"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	if (sig_arr != NULL) {
		jwt_json_t *sig_obj = jwt_json_create();

		if (sig_obj == NULL || jwt_json_arr_append(sig_arr, sig_obj))
			return 1; // LCOV_EXCL_LINE
		if (fill_sig_json(sig_obj, prot_b64, s->header, sig_b64))
			return 1; // LCOV_EXCL_LINE
	} else {
		/* Flattened: hoist the single signature to top level. */
		if (fill_sig_json(out_obj, prot_b64, s->header, sig_b64))
			return 1; // LCOV_EXCL_LINE
	}

	return 0;
}

/* @rfc{7515,7.2} Emit the JWS JSON Serialization. @jwt carries the finalized
 * shared claims (the payload) and the shared base protected header; @cmd carries
 * the signature list and the format (Flattened or General). Each signature signs
 * over BASE64URL(its own protected header) || '.' || BASE64URL(payload).
 *
 * @jwt->alg/@jwt->key are the jwt_builder_setkey() signer's, as the builder
 * callback left them (see FUNC(generate)). They make @cmd->setkey_sig's
 * signature, as they make a Compact token's. Without that node (setkey() was
 * not called, or was undone), a callback-supplied key still acts as the
 * setkey() signer: its signature comes first, ahead of the add_signature()
 * ones, which each keep their own alg/key. */
char *jwt_encode_json(jwt_t *jwt, struct jwt_common *cmd)
{
	char_auto *payload = NULL;
	char *buf = NULL;
	size_t payload_len;
	struct jwt_signature *s;
	jwt_json_auto_t *out_obj = NULL;
	jwt_json_t *sig_arr = NULL, *v;
	const jwt_alg_t p_alg = jwt->alg;
	const jwk_item_t *p_key = jwt->key;

	/* @rfc{7797} Shared payload (base64url or raw), encoded once. */
	if (jwt_build_payload_part(jwt, &payload, &payload_len)) {
		jwt_write_error(jwt, "Error encoding payload"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	out_obj = jwt_json_create();
	if (out_obj == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* @rfc{7515,7.2.1} Detached: omit "payload" (supplied out-of-band). */
	if (!jwt->detached) {
		v = jwt_json_create_str(payload);
		if (v == NULL || jwt_json_obj_set(out_obj, "payload", v))
			return NULL; // LCOV_EXCL_LINE
	}

	if (cmd->format == JWT_FORMAT_JSON_GENERAL) {
		sig_arr = jwt_json_create_arr();
		if (sig_arr == NULL || jwt_json_obj_set(out_obj, "signatures",
							sig_arr))
			return NULL; // LCOV_EXCL_LINE
	}

	/* A callback key standing in for a setkey() signer there is none of.
	 * It has no per-signature headers of its own. */
	if (cmd->setkey_sig == NULL && p_key != NULL) {
		struct jwt_signature cb_sig;

		memset(&cb_sig, 0, sizeof(cb_sig));
		if (encode_one_sig(jwt, &cb_sig, p_alg, p_key, payload,
				   payload_len, out_obj, sig_arr))
			return NULL;
	}

	list_for_each_entry(s, &cmd->signatures, node) {
		int mine = (s == cmd->setkey_sig);

		if (encode_one_sig(jwt, s, mine ? p_alg : s->alg,
				   mine ? p_key : s->key, payload,
				   payload_len, out_obj, sig_arr))
			return NULL;
	}

	buf = jwt_json_serialize(out_obj, JWT_JSON_COMPACT);
	if (buf == NULL)
		jwt_write_error(jwt, "Error serializing JWS JSON"); // LCOV_EXCL_LINE

	return buf;
}

/* @rfc{7515,4.1.11} Header Parameter names defined by RFC 7515 (the JWS
 * Protected Header) and JWA (RFC 7518). A producer MUST NOT list any of
 * these in the "crit" header. The JWA names are JWE-related and not yet
 * used by LibJWT, but are banned here for forward compatibility. */
static const char * const jwt_registered_headers[] = {
	/* RFC 7515 4.1 */
	"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256",
	"typ", "cty", "crit",
	/* RFC 7518 (JWA) */
	"enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
};

static int jwt_crit_is_registered(const char *name)
{
	size_t j;

	for (j = 0; j < ARRAY_SIZE(jwt_registered_headers); j++) {
		if (!strcmp(jwt_registered_headers[j], name))
			return 1;
	}

	return 0;
}

/* @rfc{7515,4.1.11} Validate @crit, the "crit" value of header @hdr,
 * regardless of how it got there (jwt_builder_setcrit(), set directly by
 * the application, or a signature's own). It must be a non-empty array of
 * unique strings, each naming a header parameter that is present in @hdr
 * and is not a Header Parameter name defined by RFC 7515 or JWA. */
static int jwt_validate_crit(jwt_t *jwt, const jwt_json_t *hdr,
			     jwt_json_t *crit)
{
	jwt_json_t *ent;
	size_t i, n;

	if (!jwt_json_is_array(crit)) {
		jwt_write_error(jwt, "\"crit\" header must be an array");
		return 1;
	}

	n = jwt_json_arr_size(crit);
	if (n == 0) {
		jwt_write_error(jwt, "\"crit\" header must not be empty");
		return 1;
	}

	/* Index every entry, so that none is skipped: json-c returns a JSON
	 * null one as NULL, which is not a string either. */
	for (i = 0; i < n; i++) {
		const char *name;
		size_t k;

		ent = jwt_json_arr_get(crit, i);
		if (!jwt_json_is_string(ent)) {
			jwt_write_error(jwt,
				"\"crit\" header entries must be strings");
			return 1;
		}

		name = jwt_json_str_val(ent);

		if (jwt_crit_is_registered(name)) {
			jwt_write_error(jwt,
				"\"crit\" cannot list registered header \"%s\"",
				name);
			return 1;
		}

		/* A member whose value is JSON null is in the header. */
		if (!jwt_json_obj_has(hdr, name)) {
			jwt_write_error(jwt,
				"\"crit\" lists \"%s\" which is not in the header",
				name);
			return 1;
		}

		/* Names must not be duplicated. */
		for (k = 0; k < i; k++) {
			jwt_json_t *prev = jwt_json_arr_get(crit, k);

			if (!strcmp(jwt_json_str_val(prev), name)) {
				jwt_write_error(jwt,
					"\"crit\" lists \"%s\" more than once",
					name);
				return 1;
			}
		}
	}

	return 0;
}

/* @rfc{7515,4.1.11} Emit and/or validate the "crit" (Critical) header.
 *
 * @crit is a NULL-terminated list of header parameter names the producer
 * registered via jwt_builder_setcrit(); it may be NULL. Any registered name
 * is appended to the header's "crit" array (created if needed). Regardless
 * of whether anything was registered, if the header ends up with a "crit"
 * value (e.g. the application set one directly) it is fully validated so a
 * non-conforming "crit" is never emitted.
 */
int jwt_write_crit(jwt_t *jwt, char * const *crit)
{
	jwt_json_t *arr;
	size_t i;

	arr = jwt_json_obj_get(jwt->headers, "crit");

	/* If the producer registered names, fold them into the header's
	 * "crit" array (creating it if the application didn't set one). */
	if (crit && crit[0]) {
		if (arr == NULL) {
			arr = jwt_json_create_arr();
			if (arr == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error allocating \"crit\" array");
				return 1;
				// LCOV_EXCL_STOP
			}
			/* obj_set steals the reference to arr (on success and,
			 * per the backend contract, on failure too — so we do
			 * not release it here, matching the rest of LibJWT). */
			if (jwt_json_obj_set(jwt->headers, "crit", arr)) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error setting \"crit\" in header");
				return 1;
				// LCOV_EXCL_STOP
			}
		} else if (!jwt_json_is_array(arr)) {
			/* App set a non-array "crit"; can't append to it.
			 * Let validation below report the error. */
			return jwt_validate_crit(jwt, jwt->headers, arr);
		}

		for (i = 0; crit[i] != NULL; i++) {
			jwt_json_t *str = jwt_json_create_str(crit[i]);

			if (str == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error allocating \"crit\" entry");
				return 1;
				// LCOV_EXCL_STOP
			}

			/* Append steals the reference to str. */
			jwt_json_arr_append(arr, str);
		}
	}

	/* Nothing registered and the app set no "crit": nothing to do. */
	if (arr == NULL)
		return 0;

	return jwt_validate_crit(jwt, jwt->headers, arr);
}

int jwt_head_setup(jwt_t *jwt)
{
	jwt_value_t jval;

	if (jwt->alg != JWT_ALG_NONE) {

		/* Only set default 'typ' header if it has not been defined,
		 * allowing for any value of it. This allows for signaling
		 * of application specific extensions to JWT, such as PASSporT,
		 * RFC 8225. */
		jwt_set_SET_STR(&jval, "typ", "JWT");
		if (jwt_header_set(jwt, &jval)) {
			if (jval.error != JWT_VALUE_ERR_EXIST) {
				// LCOV_EXCL_START
				jwt_write_error(jwt,
					"Error setting \"typ\" in header");
				return 1;
				// LCOV_EXCL_STOP
			}
		}
	}

	jwt_set_SET_STR(&jval, "alg", jwt_alg_str(jwt->alg));
	jval.replace = 1;
	if (jwt_header_set(jwt, &jval)) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error setting \"alg\" in header");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

/* @rfc{7797} Build the payload as it appears after the first '.': the raw
 * payload bytes (jwt_builder_setpayload()) or the serialized claims, then
 * base64url-encoded unless b64 is false. Returns a malloc'd, NUL-terminated
 * buffer (binary-safe via @out_len). 0 on success. */
int jwt_build_payload_part(jwt_t *jwt, char **out, size_t *out_len)
{
	const unsigned char *bytes;
	char_auto *claims_str = NULL;
	size_t len;

	if (jwt->payload_raw != NULL) {
		bytes = jwt->payload_raw;
		len = jwt->payload_raw_len;
	} else {
		if (write_js(jwt->claims, &claims_str))
			return 1; // LCOV_EXCL_LINE
		bytes = (const unsigned char *)claims_str;
		len = strlen(claims_str);
	}

	if (jwt->b64) {
		int n;

		if (len > INT_MAX)
			return 1; // LCOV_EXCL_LINE
		n = jwt_base64uri_encode(out, (const char *)bytes, (int)len);
		if (n <= 0)
			return 1; // LCOV_EXCL_LINE
		/* The return counts stripped '=' padding; the string is shorter. */
		*out_len = strlen(*out);
	} else {
		char *copy = jwt_malloc(len + 1);

		if (copy == NULL)
			return 1; // LCOV_EXCL_LINE
		memcpy(copy, bytes, len);
		copy[len] = '\0';
		*out = copy;
		*out_len = len;
	}

	return 0;
}

/* @rfc{7797,6} For an unencoded payload, the protected header must carry
 * "b64":false and "b64" MUST be marked critical. Inject both into @jwt->headers
 * (the shared base, which the compact path signs directly and the JSON path
 * clones into each signature). */
int jwt_apply_b64_header(jwt_t *jwt)
{
	jwt_json_t *crit, *ent, *v;
	size_t i;
	int found = 0;

	v = jwt_json_create_bool(0);
	if (v == NULL || jwt_json_obj_set(jwt->headers, "b64", v))
		return 1; // LCOV_EXCL_LINE

	crit = jwt_json_obj_get(jwt->headers, "crit");
	if (crit == NULL) {
		crit = jwt_json_create_arr();
		if (crit == NULL || jwt_json_obj_set(jwt->headers, "crit", crit))
			return 1; // LCOV_EXCL_LINE
	} else if (!jwt_json_is_array(crit)) {
		jwt_write_error(jwt, "\"crit\" header must be an array");
		return 1;
	}

	jwt_json_arr_foreach(crit, i, ent) {
		if (jwt_json_is_string(ent) &&
		    !strcmp(jwt_json_str_val(ent), "b64")) {
			found = 1;
			break;
		}
	}
	if (!found) {
		v = jwt_json_create_str("b64");
		if (v == NULL || jwt_json_arr_append(crit, v))
			return 1; // LCOV_EXCL_LINE
	}

	return 0;
}

static int jwt_encode(jwt_t *jwt, char **out)
{
	char_auto *head = NULL, *payload = NULL, *sig_b64 = NULL;
	char *buf = NULL, *si = NULL, *token = NULL, *p;
	int head_len, ret;
	size_t payload_len, si_len, pout_len, token_len, sb_len;
	unsigned int sig_len;

	if (out == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "No string passed to write out to");
		return 1;
		// LCOV_EXCL_STOP
	}
	*out = NULL;

	/* Header. */
	if (write_js(jwt->headers, &buf))
		return 1; // LCOV_EXCL_LINE
	head_len = jwt_base64uri_encode(&head, buf, (int)strlen(buf));
	jwt_freemem(buf);
	if (head_len <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(jwt, "Error encoding header");
		return 1;
		// LCOV_EXCL_STOP
	}
	/* The return counts stripped '=' padding; use the true string length. */
	head_len = (int)strlen(head);

	/* @rfc{7797} Payload part (base64url or raw). */
	if (jwt_build_payload_part(jwt, &payload, &payload_len)) {
		jwt_write_error(jwt, "Error encoding payload"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	if ((size_t)head_len > SIZE_MAX - payload_len - 2) {
		jwt_write_error(jwt, "Encoded token too large"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	/* Signing input: BASE64URL(header) "." payload (binary-safe). */
	si_len = (size_t)head_len + 1 + payload_len;
	si = jwt_malloc(si_len + 1);
	if (si == NULL) {
		jwt_write_error(jwt, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}
	memcpy(si, head, head_len);
	si[head_len] = '.';
	memcpy(si + head_len + 1, payload, payload_len);
	si[si_len] = '\0';

	/* Signature (empty for an unsecured "none" token). */
	if (jwt->alg == JWT_ALG_NONE) {
		sig_b64 = jwt_malloc(1);
		if (sig_b64 != NULL)
			sig_b64[0] = '\0';
	} else {
		char *rawsig = NULL;

		ret = jwt_sign(jwt, &rawsig, &sig_len, si, si_len);
		if (ret) {
			jwt_freemem(si);
			return ret;
		}
		ret = jwt_base64uri_encode(&sig_b64, rawsig, sig_len);
		jwt_freemem(rawsig);
		if (ret < 0) {
			jwt_write_error(jwt, "Error encoding signature"); // LCOV_EXCL_LINE
			jwt_freemem(si); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}
	}
	jwt_freemem(si);

	if (sig_b64 == NULL) {
		jwt_write_error(jwt, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	/* @rfc{7797} Assemble: header "." (detached ? "" : payload) "." sig. */
	sb_len = strlen(sig_b64);
	pout_len = jwt->detached ? 0 : payload_len;
	token_len = (size_t)head_len + 1 + pout_len + 1 + sb_len;	token = jwt_malloc(token_len + 1);
	if (token == NULL) {
		jwt_write_error(jwt, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}
	p = token;
	memcpy(p, head, head_len);
	p += head_len;
	*p++ = '.';
	if (pout_len) {
		memcpy(p, payload, pout_len);
		p += pout_len;
	}
	*p++ = '.';
	memcpy(p, sig_b64, sb_len);
	p += sb_len;
	*p = '\0';

	*out = token;

	return 0;
}

char *jwt_encode_str(jwt_t *jwt)
{
	char *str = NULL;

	if (jwt_encode(jwt, &str))
		jwt_freemem(str);

	return str;
}
