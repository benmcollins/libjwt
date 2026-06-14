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
	struct jwe_recipient *r, *tmp;

	if (__cmd == NULL)
		return;

	jwt_json_release(__cmd->c.payload);
	jwt_json_release(__cmd->c.headers);
	jwt_json_release(__cmd->c.unprotected);

	/* @rfc{7516,7.2.1} Free every recipient (and its owned key material). */
	list_for_each_entry_safe(r, tmp, &__cmd->c.recipients, node) {
		list_del(&r->node);
		jwe_recipient_free(r);
	}

	/* Scrub sensitive key material. The CEK is secret; the other
	 * components are not, but free them all here. */
	jwt_scrub_and_free(__cmd->c.cek, __cmd->c.cek_len);
	jwt_freemem(__cmd->c.iv);
	jwt_freemem(__cmd->c.ct);
	jwt_freemem(__cmd->c.tag);
	jwt_scrub_and_free(__cmd->c.aad, __cmd->c.aad_len);
	jwt_freemem(__cmd->c.aad_b64);
	jwt_scrub_and_free(__cmd->c.recovered_aad, __cmd->c.recovered_aad_len);

	memset(__cmd, 0, sizeof(*__cmd));

	jwt_freemem(__cmd);
}

jwe_common_t *FUNC(new)(void)
{
	jwe_common_t *__cmd = jwt_malloc(sizeof(*__cmd));

	if (__cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(__cmd, 0, sizeof(*__cmd));

	INIT_LIST_HEAD(&__cmd->c.recipients);
	__cmd->c.format = JWE_FORMAT_COMPACT;

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
	struct jwe_recipient *r;
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

	/* @rfc{7516,7.2.1} setkey configures the first (and, for Compact, only)
	 * recipient. Calling it again replaces that recipient's alg/key. */
	r = jwe_recipient_first_or_add(&__cmd->c);
	if (r == NULL) {
		jwt_write_error(__cmd, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	r->key_alg = alg;
	r->key = key;
	__cmd->c.enc = enc;

	return 0;
}

#ifdef JWE_BUILDER
/* @rfc{7518,4.6.2} Store apu/apv as base64url for emission in the header and
 * binding into the Concat KDF. NULL/0 leaves a field unset; calling again
 * replaces previous values. */
int FUNC(set_partyinfo)(jwe_common_t *__cmd,
			const unsigned char *apu, size_t apu_len,
			const unsigned char *apv, size_t apv_len)
{
	struct jwe_recipient *r;
	char *apu_b64 = NULL, *apv_b64 = NULL;

	if (__cmd == NULL)
		return 1;

	/* @rfc{7518,4.6.2} Party info targets the first recipient (the one set
	 * by setkey). Create it if setkey has not run yet. */
	r = jwe_recipient_first_or_add(&__cmd->c);
	if (r == NULL) {
		jwt_write_error(__cmd, "Error allocating memory"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	if (apu && apu_len &&
	    jwt_base64uri_encode(&apu_b64, (const char *)apu, (int)apu_len) <= 0)
		goto oom; // LCOV_EXCL_LINE
	if (apv && apv_len &&
	    jwt_base64uri_encode(&apv_b64, (const char *)apv, (int)apv_len) <= 0)
		goto oom; // LCOV_EXCL_LINE

	jwt_freemem(r->apu);
	jwt_freemem(r->apv);
	r->apu = apu_b64;
	r->apv = apv_b64;

	return 0;

	// LCOV_EXCL_START
oom:
	jwt_freemem(apu_b64);
	jwt_freemem(apv_b64);
	jwt_write_error(__cmd, "Error encoding apu/apv");
	return 1;
	// LCOV_EXCL_STOP
}

/* @rfc{7516,4.1} Header parameter names the library manages itself and that an
 * application must not set via add_protected_json / add_unprotected_json:
 * "enc" lives in the protected header; "alg"/"epk"/"apu"/"apv" are placed in
 * the per-recipient header by setkey/set_partyinfo and the ECDH-ES agreement. */
static int jwe_header_name_reserved(const char *key)
{
	return !strcmp(key, "alg") || !strcmp(key, "enc") ||
	       !strcmp(key, "epk") || !strcmp(key, "apu") ||
	       !strcmp(key, "apv");
}

/* Parse @value_json (a JSON fragment) and set it on @obj under @key. Rejects a
 * reserved name, a NULL arg, a parse failure, and a duplicate key already in
 * @obj. JWT_JSON_DECODE_ANY lets a value be any JSON type, including a bare
 * scalar. Returns 0 on success, non-zero (with the builder error set) on
 * failure. */
static int FUNC(add_header_json)(jwe_common_t *__cmd, jwt_json_t *obj,
				 const char *key, const char *value_json)
{
	jwt_json_t *val;

	/* The public wrappers (add_protected_json / add_unprotected_json) guard
	 * a NULL builder before reaching this static helper. */
	if (__cmd == NULL)
		return 1; // LCOV_EXCL_LINE

	if (key == NULL || value_json == NULL) {
		jwt_write_error(__cmd, "Header key and value are required");
		return 1;
	}

	if (jwe_header_name_reserved(key)) {
		jwt_write_error(__cmd,
			"Header parameter \"%s\" is reserved by the library",
			key);
		return 1;
	}

	if (jwt_json_obj_get(obj, key) != NULL) {
		jwt_write_error(__cmd,
			"Header parameter \"%s\" is already set", key);
		return 1;
	}

	val = jwt_json_parse(value_json, JWT_JSON_DECODE_ANY, NULL);
	if (val == NULL) {
		jwt_write_error(__cmd, "Could not parse header value as JSON");
		return 1;
	}

	/* obj_set steals the reference to val on success and on failure. */
	if (jwt_json_obj_set(obj, key, val)) {
		jwt_write_error(__cmd, "Could not set header parameter"); // LCOV_EXCL_LINE
		return 1; // LCOV_EXCL_LINE
	}

	return 0;
}

/* @rfc{7516,7.2.1} Add an application parameter to the protected header. */
int FUNC(add_protected_json)(jwe_common_t *__cmd, const char *key,
			     const char *value_json)
{
	if (__cmd == NULL)
		return 1;

	return FUNC(add_header_json)(__cmd, __cmd->c.headers, key, value_json);
}

/* @rfc{7516,7.2.1} Add an application parameter to the shared unprotected
 * header, creating that header object on first use. */
int FUNC(add_unprotected_json)(jwe_common_t *__cmd, const char *key,
			       const char *value_json)
{
	if (__cmd == NULL)
		return 1;

	if (__cmd->c.unprotected == NULL) {
		__cmd->c.unprotected = jwt_json_create();
		if (__cmd->c.unprotected == NULL) {
			jwt_write_error(__cmd, "Error allocating memory"); // LCOV_EXCL_LINE
			return 1; // LCOV_EXCL_LINE
		}
	}

	return FUNC(add_header_json)(__cmd, __cmd->c.unprotected, key,
				    value_json);
}

/* @rfc{7516,4.1.4} Select the serialization to emit. */
int FUNC(set_format)(jwe_common_t *__cmd, jwe_serialization_t format)
{
	if (__cmd == NULL)
		return 1;

	if (format != JWE_FORMAT_COMPACT && format != JWE_FORMAT_JSON_FLAT &&
	    format != JWE_FORMAT_JSON_GENERAL) {
		jwt_write_error(__cmd, "Invalid JWE serialization format");
		return 1;
	}

	__cmd->c.format = format;

	return 0;
}

/* @rfc{7516,5.1} step 14 Store the application AAD (the "aad" member). Keep both
 * the raw octets (for symmetry / future accessors) and the base64url form that
 * is emitted and concatenated into the AEAD AAD. NULL clears it. */
int FUNC(set_aad)(jwe_common_t *__cmd, const unsigned char *aad, size_t aad_len)
{
	unsigned char *raw = NULL;
	char *b64 = NULL;

	if (__cmd == NULL)
		return 1;

	if (aad != NULL && aad_len) {
		raw = jwt_malloc(aad_len);
		if (raw == NULL)
			goto oom; // LCOV_EXCL_LINE
		memcpy(raw, aad, aad_len);

		if (jwt_base64uri_encode(&b64, (const char *)aad,
					 (int)aad_len) <= 0)
			goto oom; // LCOV_EXCL_LINE
	}

	jwt_scrub_and_free(__cmd->c.aad, __cmd->c.aad_len);
	jwt_freemem(__cmd->c.aad_b64);
	__cmd->c.aad = raw;
	__cmd->c.aad_len = raw ? aad_len : 0;
	__cmd->c.aad_b64 = b64;

	return 0;

	// LCOV_EXCL_START
oom:
	jwt_scrub_and_free(raw, aad_len);
	jwt_freemem(b64);
	jwt_write_error(__cmd, "Error storing JWE AAD");
	return 1;
	// LCOV_EXCL_STOP
}
#endif

#ifdef JWE_BUILDER
/* @rfc{7516,7.1} Assemble the five-part Compact Serialization from the encoded
 * segments. The Encrypted Key is empty for dir / ECDH-ES Direct. */
static char *jwe_assemble_compact(const char *hdr_b64, const char *ek_b64,
				  const char *iv_b64, const char *ct_b64,
				  const char *tag_b64)
{
	const char *ek = ek_b64 ? ek_b64 : "";
	char *out;

	out = jwt_malloc(strlen(hdr_b64) + strlen(ek) + strlen(iv_b64) +
			 strlen(ct_b64) + strlen(tag_b64) + 5);
	if (out == NULL)
		return NULL; // LCOV_EXCL_LINE

	sprintf(out, "%s.%s.%s.%s.%s", hdr_b64, ek, iv_b64, ct_b64, tag_b64);

	return out;
}

/* @rfc{7516,7.2} Assemble a JSON Serialization. @recip_hdr is the single
 * recipient's per-recipient header (may be NULL/empty) and @ek_b64 its
 * Encrypted Key (NULL for dir / ECDH-ES Direct). For JWE_FORMAT_JSON_FLAT the
 * header and encrypted_key are hoisted to the top level; for
 * JWE_FORMAT_JSON_GENERAL they go inside a one-element "recipients" array.
 * Returns a newly allocated string or NULL on error. */
static char *FUNC(assemble_json)(jwe_common_t *__cmd, const char *hdr_b64,
				 jwt_json_t *recip_hdr, const char *ek_b64,
				 const char *iv_b64, const char *ct_b64,
				 const char *tag_b64)
{
	jwt_json_auto_t *obj = NULL;
	jwt_json_t *rcp_arr = NULL, *rcp = NULL;
	int recip_hdr_used = 0;
	char *out = NULL;

	obj = jwt_json_create();
	if (obj == NULL)
		goto oom; // LCOV_EXCL_LINE

	/* Members shared by both JSON forms. */
	if (jwt_json_obj_set(obj, "protected", jwt_json_create_str(hdr_b64)))
		goto oom; // LCOV_EXCL_LINE
	if (__cmd->c.unprotected != NULL) {
		jwt_json_t *cl = jwt_json_clone(__cmd->c.unprotected);
		if (cl == NULL || jwt_json_obj_set(obj, "unprotected", cl))
			goto oom; // LCOV_EXCL_LINE
	}
	if (__cmd->c.aad_b64 != NULL &&
	    jwt_json_obj_set(obj, "aad", jwt_json_create_str(__cmd->c.aad_b64)))
		goto oom; // LCOV_EXCL_LINE
	if (jwt_json_obj_set(obj, "iv", jwt_json_create_str(iv_b64)) ||
	    jwt_json_obj_set(obj, "ciphertext", jwt_json_create_str(ct_b64)) ||
	    jwt_json_obj_set(obj, "tag", jwt_json_create_str(tag_b64)))
		goto oom; // LCOV_EXCL_LINE

	/* A non-empty per-recipient header is emitted; an empty one is omitted. */
	if (recip_hdr != NULL && jwt_json_obj_get(recip_hdr, "alg") != NULL)
		recip_hdr_used = 1;

	if (__cmd->c.format == JWE_FORMAT_JSON_FLAT) {
		/* @rfc{7516,7.2.2} Flattened: header / encrypted_key at top level. */
		if (recip_hdr_used) {
			jwt_json_t *cl = jwt_json_clone(recip_hdr);
			if (cl == NULL || jwt_json_obj_set(obj, "header", cl))
				goto oom; // LCOV_EXCL_LINE
		}
		if (ek_b64 != NULL &&
		    jwt_json_obj_set(obj, "encrypted_key",
				     jwt_json_create_str(ek_b64)))
			goto oom; // LCOV_EXCL_LINE
	} else {
		/* @rfc{7516,7.2.1} General: a one-element "recipients" array. */
		rcp_arr = jwt_json_create_arr();
		if (rcp_arr == NULL || jwt_json_obj_set(obj, "recipients", rcp_arr))
			goto oom; // LCOV_EXCL_LINE

		rcp = jwt_json_create();
		if (rcp == NULL || jwt_json_arr_append(rcp_arr, rcp))
			goto oom; // LCOV_EXCL_LINE

		if (recip_hdr_used) {
			jwt_json_t *cl = jwt_json_clone(recip_hdr);
			if (cl == NULL || jwt_json_obj_set(rcp, "header", cl))
				goto oom; // LCOV_EXCL_LINE
		}
		if (ek_b64 != NULL &&
		    jwt_json_obj_set(rcp, "encrypted_key",
				     jwt_json_create_str(ek_b64)))
			goto oom; // LCOV_EXCL_LINE
	}

	/* The protected header was already serialized with sorted keys; the
	 * outer object is just compacted (RFC 7520 JSON vectors are unsorted, so
	 * output is not byte-compared to them). */
	out = jwt_json_serialize(obj, JWT_JSON_COMPACT);
	if (out == NULL)
		goto oom; // LCOV_EXCL_LINE

	return out;

	// LCOV_EXCL_START
oom:
	jwt_write_error(__cmd, "Error building JWE JSON");
	return NULL;
	// LCOV_EXCL_STOP
}

/* @rfc{7516,5.1} Encrypt @plaintext into a JWE. The Compact Serialization is
 * produced unless a JSON format was selected with set_format. */
char *FUNC(generate)(jwe_common_t *__cmd, const unsigned char *plaintext,
		     size_t plaintext_len)
{
	struct jwe_recipient *recip;
	jwt_json_auto_t *hdr = NULL;
	jwt_json_t *kmhdr;
	char_auto *hdr_json = NULL, *hdr_b64 = NULL, *ek_b64 = NULL;
	char_auto *iv_b64 = NULL, *ct_b64 = NULL, *tag_b64 = NULL;
	unsigned char *cek = NULL, *iv = NULL, *ct = NULL, *tag = NULL;
	unsigned char *enckey = NULL;
	const unsigned char *aad = NULL;
	size_t cek_len = 0, iv_len, ct_len = 0, tag_len = 0, enckey_len = 0;
	size_t aad_len = 0;
	int aad_owned = 0, is_json;
	const unsigned char *k;
	char *out = NULL;
	int hdr_len, ret;

	if (__cmd == NULL)
		return NULL;

	/* @rfc{7516,7.2.1} The Compact and Flattened serializations have exactly
	 * one recipient, configured via setkey. */
	recip = jwe_recipient_first(&__cmd->c);
	if (recip == NULL || recip->key == NULL ||
	    recip->key_alg == JWE_ALG_NONE) {
		jwt_write_error(__cmd, "No key/algorithm set");
		return NULL;
	}

	if (plaintext == NULL && plaintext_len) {
		jwt_write_error(__cmd, "No plaintext given");
		return NULL;
	}

	is_json = (__cmd->c.format != JWE_FORMAT_COMPACT);

	/* @rfc{7516,7.1} The Compact Serialization cannot carry a shared
	 * unprotected header or a JWE AAD member; only the JSON serializations
	 * can. (Multi-recipient is enforced in a later stage.) */
	if (!is_json &&
	    (__cmd->c.unprotected != NULL || __cmd->c.aad_b64 != NULL)) {
		jwt_write_error(__cmd,
			"Compact Serialization cannot carry unprotected header or aad");
		return NULL;
	}

	/* @rfc{7516,5.1} step 12-13: build the protected header. It always
	 * carries "enc". For the Compact Serialization the key-management
	 * parameters ("alg", and the ECDH-ES "epk"/"apu"/"apv") also live in the
	 * protected header, so they are bound into the single AAD. For the JSON
	 * serializations they belong in the per-recipient header instead, since
	 * each recipient agrees its own "epk". @kmhdr is whichever object
	 * receives those key-management parameters. */
	hdr = jwt_json_create();
	if (hdr == NULL)
		goto oom; // LCOV_EXCL_LINE
	if (jwt_json_obj_set(hdr, "enc",
			     jwt_json_create_str(jwe_enc_str(__cmd->c.enc)))) {
		jwt_write_error(__cmd, "Error building JWE header"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	if (is_json) {
		if (recip->header == NULL) {
			recip->header = jwt_json_create();
			if (recip->header == NULL)
				goto oom; // LCOV_EXCL_LINE
		}
		kmhdr = recip->header;
	} else {
		kmhdr = hdr;
	}

	if (jwt_json_obj_set(kmhdr, "alg",
			     jwt_json_create_str(jwe_alg_str(recip->key_alg))))
		goto oom; // LCOV_EXCL_LINE

	/* @rfc{7518,4.6.2} For ECDH-ES, emit any apu/apv into the key-management
	 * header before the agreement runs, so they are bound into the Concat
	 * KDF. */
	if (jwe_alg_is_ecdh(recip->key_alg)) {
		if (recip->apu &&
		    jwt_json_obj_set(kmhdr, "apu",
				     jwt_json_create_str(recip->apu)))
			goto oom; // LCOV_EXCL_LINE
		if (recip->apv &&
		    jwt_json_obj_set(kmhdr, "apv",
				     jwt_json_create_str(recip->apv)))
			goto oom; // LCOV_EXCL_LINE
	}

	/* @rfc{7518,4.6} ECDH-ES (Direct): derive the CEK and add the "epk"
	 * to the key-management header BEFORE the protected header is serialized,
	 * since the protected header bytes are (part of) the AAD. The Encrypted
	 * Key stays empty (like dir). */
	if (jwe_alg_is_ecdh(recip->key_alg)) {
		/* @rfc{7518,4.6} Derive the agreed key and emit "epk" while the
		 * header object can still be modified. For Direct mode the
		 * agreed key is the CEK; for +A*KW it is the KEK. */
		unsigned char *agreed = NULL;
		size_t agreed_len = 0;

		if (jwe_ecdh_derive(recip->key_alg, __cmd->c.enc,
				    recip->key, 1, kmhdr, &agreed, &agreed_len)) {
			jwt_write_error(__cmd, "ECDH-ES key agreement failed");
			return NULL;
		}

		if (jwe_alg_is_ecdh_direct(recip->key_alg)) {
			cek = agreed;
			cek_len = agreed_len;
		} else {
			/* +A*KW: wrap a fresh CEK with the agreed KEK. */
			int werr;

			if (jwe_generate_cek(__cmd->c.enc, &cek, &cek_len)) {
				// LCOV_EXCL_START
				jwt_scrub_and_free(agreed, agreed_len);
				jwt_write_error(__cmd, "Could not generate CEK");
				return NULL;
				// LCOV_EXCL_STOP
			}
			werr = jwe_aeskw_wrap_raw(agreed, agreed_len, cek,
						 cek_len, &enckey, &enckey_len);
			jwt_scrub_and_free(agreed, agreed_len);
			if (werr) {
				jwt_write_error(__cmd, "ECDH-ES key wrap failed"); // LCOV_EXCL_LINE
				goto fail; // LCOV_EXCL_LINE
			}
		}
	}

	hdr_json = jwt_json_serialize(hdr, JWT_JSON_SORT_KEYS | JWT_JSON_COMPACT);
	if (hdr_json == NULL)
		goto oom; // LCOV_EXCL_LINE

	hdr_len = jwt_base64uri_encode(&hdr_b64, hdr_json, (int)strlen(hdr_json));
	if (hdr_len <= 0)
		goto oom; // LCOV_EXCL_LINE

	/* @rfc{7516,5.1} Produce the CEK and the JWE Encrypted Key per the key
	 * management algorithm. */
	if (jwe_alg_is_ecdh(recip->key_alg)) {
		/* ECDH-ES: the CEK (Direct) or CEK+Encrypted Key (+A*KW) was
		 * already produced above, before the header was serialized. */
	} else if (recip->key_alg == JWE_ALG_DIR) {
		/* dir: the CEK is the shared symmetric key; Encrypted Key is
		 * empty. */
		size_t need = jwe_enc_cek_len(__cmd->c.enc);

		ret = jwks_item_key_oct(recip->key, &k, &cek_len);
		if (ret || k == NULL || cek_len != need) {
			jwt_write_error(__cmd,
				"dir key length does not match enc");
			return NULL;
		}
		cek = jwt_malloc(cek_len);
		if (cek == NULL)
			goto oom; // LCOV_EXCL_LINE
		memcpy(cek, k, cek_len);
	} else {
		/* A*KW / RSA-OAEP: generate a random CEK and wrap or encrypt it
		 * to the recipient. */
		if (jwe_generate_cek(__cmd->c.enc, &cek, &cek_len)) {
			// LCOV_EXCL_START
			jwt_write_error(__cmd, "Could not generate CEK");
			return NULL;
			// LCOV_EXCL_STOP
		}
		if (jwe_encrypt_cek(recip->key_alg, recip->key, cek, cek_len,
				    &enckey, &enckey_len)) {
			jwt_write_error(__cmd, "Could not encrypt the CEK");
			goto fail;
		}
	}

	/* Encode the Encrypted Key (empty for dir). */
	if (enckey_len &&
	    jwt_base64uri_encode(&ek_b64, (char *)enckey, (int)enckey_len) <= 0)
		goto oom; // LCOV_EXCL_LINE

	/* @rfc{7516,5.1} step 9: generate the IV. */
	iv_len = jwe_enc_iv_len(__cmd->c.enc);
	iv = jwt_malloc(iv_len);
	if (iv == NULL)
		goto oom; // LCOV_EXCL_LINE
	if (jwt_ops->rng == NULL || jwt_ops->rng(iv, iv_len)) {
		// LCOV_EXCL_START
		jwt_write_error(__cmd, "JWE not supported by crypto backend");
		goto fail;
		// LCOV_EXCL_STOP
	}

	/* @rfc{7516,5.1} step 14-15: build the AAD and encrypt the content. For
	 * the Compact Serialization there is no "aad" member, so jwe_build_aad
	 * aliases hdr_b64 (byte-identical). For the JSON serializations a present
	 * "aad" member appends '.' || BASE64URL(aad). */
	if (jwe_build_aad(hdr_b64, __cmd->c.aad_b64, &aad, &aad_len, &aad_owned))
		goto oom; // LCOV_EXCL_LINE
	ret = jwe_encrypt_content(__cmd->c.enc, cek, cek_len, iv, iv_len,
				  aad, aad_len, plaintext, plaintext_len,
				  &ct, &ct_len, &tag, &tag_len);
	if (ret) {
		// LCOV_EXCL_START
		jwt_write_error(__cmd, "Content encryption failed");
		goto fail;
		// LCOV_EXCL_STOP
	}

	/* Encode the binary parts. */
	if (jwt_base64uri_encode(&iv_b64, (char *)iv, (int)iv_len) <= 0 ||
	    jwt_base64uri_encode(&ct_b64, (char *)ct, (int)ct_len) <= 0 ||
	    jwt_base64uri_encode(&tag_b64, (char *)tag, (int)tag_len) <= 0)
		goto oom; // LCOV_EXCL_LINE

	/* @rfc{7516,7} Assemble in the configured serialization. assemble_json
	 * sets its own error; the compact path only fails on OOM. */
	if (is_json) {
		out = FUNC(assemble_json)(__cmd, hdr_b64, recip->header, ek_b64,
					  iv_b64, ct_b64, tag_b64);
		if (out == NULL)
			goto fail; // LCOV_EXCL_LINE
	} else {
		out = jwe_assemble_compact(hdr_b64, ek_b64, iv_b64, ct_b64,
					   tag_b64);
		if (out == NULL)
			goto oom; // LCOV_EXCL_LINE
	}

	goto done;

	// LCOV_EXCL_START
oom:
	jwt_write_error(__cmd, "Error allocating memory");
	// LCOV_EXCL_STOP
fail:
	out = NULL;
done:
	if (aad_owned) {
		void *aad_free = (void *)(uintptr_t)aad;
		jwt_freemem(aad_free);
	}
	jwt_scrub_and_free(cek, cek_len);
	jwt_freemem(enckey);
	jwt_freemem(iv);
	jwt_freemem(ct);
	jwt_freemem(tag);

	return out;
}
#endif

#ifdef JWE_CHECKER
/* Find the next '.' in @p, niling it and returning the start of the field
 * after it; or NULL if no dot remains. Used to split the 5 compact parts. */
static char *split_dot(char *p)
{
	for (; *p; p++) {
		if (*p == '.') {
			*p = '\0';
			return p + 1;
		}
	}
	return NULL;
}

/* @rfc{7516,5.2} Recover the CEK and decrypt the content for one recipient.
 * Shared by the Compact and JSON serialization paths. Inputs are the decoded
 * b64 segments (as nil-terminated strings) plus @eff_hdr, the effective header
 * the ECDH-ES "epk" is read from (the protected header for Compact, the
 * per-recipient header for JSON). @ek_b64 may be "" or NULL when there is no
 * Encrypted Key (dir / ECDH-ES Direct). @aad_b64 is the JSON "aad" member's
 * base64url (NULL for Compact). Returns a newly allocated nil-terminated
 * plaintext buffer or NULL on error, with the error set in @__cmd.
 *
 * @rfc{7516,11.5} All CEK-recovery failures funnel to a random CEK so the AEAD
 * tag fails uniformly; the only post-CEK error is the generic auth failure. */
static unsigned char *FUNC(recover_and_decrypt)(jwe_common_t *__cmd,
		struct jwe_recipient *recip, jwt_json_t *eff_hdr,
		jwe_key_alg_t alg, jwe_enc_t enc, const char *protected_b64,
		const char *aad_b64, const char *ek_b64, const char *iv_b64,
		const char *ct_b64, const char *tag_b64, size_t *plaintext_len)
{
	unsigned char *cek = NULL, *iv = NULL, *ct = NULL, *tag = NULL;
	unsigned char *pt = NULL, *out = NULL, *enckey = NULL;
	const unsigned char *aad = NULL;
	size_t cek_len = 0, pt_len = 0, aad_len = 0;
	int iv_len = 0, ct_len = 0, tag_len = 0, ek_len = 0, aad_owned = 0;
	int have_ek = (ek_b64 != NULL && *ek_b64 != '\0');
	const unsigned char *k;

	/* @rfc{7516,5.2} CEK per the key management algorithm. */
	if (jwe_alg_is_ecdh(alg)) {
		/* @rfc{7518,4.6} Derive the agreed key from the recipient
		 * private key and the effective header's "epk". */
		unsigned char *agreed = NULL;
		size_t agreed_len = 0, need = jwe_enc_cek_len(enc);

		if (jwe_alg_is_ecdh_direct(alg) && have_ek) {
			jwt_write_error(__cmd,
				"ECDH-ES (Direct) must have an empty Encrypted Key");
			return NULL;
		}
		if (!jwe_alg_is_ecdh_direct(alg) && !have_ek) {
			jwt_write_error(__cmd,
				"ECDH-ES+A*KW requires an Encrypted Key");
			return NULL;
		}

		/* A failed agreement (bad/missing epk, curve mismatch) is a
		 * structural error, not a key-recovery oracle. */
		if (jwe_ecdh_derive(alg, enc, recip->key, 0, eff_hdr,
				    &agreed, &agreed_len)) {
			jwt_write_error(__cmd, "ECDH-ES key agreement failed");
			goto fail;
		}

		if (jwe_alg_is_ecdh_direct(alg)) {
			cek = agreed;
			cek_len = agreed_len;
			if (cek_len != need) {
				jwt_write_error(__cmd, "Derived CEK length wrong"); // LCOV_EXCL_LINE
				goto fail; // LCOV_EXCL_LINE
			}
		} else {
			/* +A*KW: unwrap the CEK with the agreed KEK. @rfc{7516,11.5}
			 * On any unwrap failure, substitute a random CEK and let
			 * the AEAD tag fail uniformly. */
			int bad = 0;

			enckey = jwt_base64uri_decode(ek_b64, &ek_len);
			if (enckey == NULL || ek_len <= 0)
				bad = 1;
			else if (jwe_aeskw_unwrap_raw(agreed, agreed_len, enckey,
						      ek_len, &cek, &cek_len))
				bad = 1;
			else if (cek_len != need)
				bad = 1; // LCOV_EXCL_LINE

			jwt_scrub_and_free(agreed, agreed_len);

			if (bad) {
				jwt_scrub_and_free(cek, cek_len);
				cek = NULL;
				cek_len = 0;
				if (jwe_generate_cek(enc, &cek, &cek_len))
					goto oom; // LCOV_EXCL_LINE
			}
		}
	} else if (alg == JWE_ALG_DIR) {
		size_t need = jwe_enc_cek_len(enc);

		if (have_ek) {
			jwt_write_error(__cmd,
				"dir must have an empty Encrypted Key");
			return NULL;
		}
		if (jwks_item_key_oct(recip->key, &k, &cek_len) ||
		    k == NULL || cek_len != need) {
			jwt_write_error(__cmd,
				"dir key length does not match enc");
			return NULL;
		}
		cek = jwt_malloc(cek_len);
		if (cek == NULL)
			goto oom; // LCOV_EXCL_LINE
		memcpy(cek, k, cek_len);
	} else {
		/* A*KW / RSA-OAEP: the Encrypted Key carries the CEK. */
		size_t need = jwe_enc_cek_len(enc);
		int bad = 0;

		if (!have_ek) {
			jwt_write_error(__cmd,
				"Key management requires an Encrypted Key");
			return NULL;
		}

		enckey = jwt_base64uri_decode(ek_b64, &ek_len);
		if (enckey == NULL || ek_len <= 0)
			bad = 1;
		else if (jwe_decrypt_cek(alg, recip->key, enckey, ek_len,
					 &cek, &cek_len))
			bad = 1;
		else if (cek_len != need)
			bad = 1; // LCOV_EXCL_LINE

		/* @rfc{7516,11.5} Do not reveal why CEK recovery failed: a
		 * padding/format/length error would otherwise be an oracle
		 * (e.g. Bleichenbacher against RSA). On any failure, substitute
		 * a random CEK of the correct length and proceed; the AEAD tag
		 * check below then fails uniformly, indistinguishable from a
		 * merely-wrong key. */
		if (bad) {
			jwt_scrub_and_free(cek, cek_len);
			cek = NULL;
			cek_len = 0;
			if (jwe_generate_cek(enc, &cek, &cek_len))
				goto oom; // LCOV_EXCL_LINE
		}
	}

	/* Decode IV, ciphertext, tag. */
	iv = jwt_base64uri_decode(iv_b64, &iv_len);
	ct = jwt_base64uri_decode(ct_b64, &ct_len);
	tag = jwt_base64uri_decode(tag_b64, &tag_len);
	if (iv == NULL || ct == NULL || tag == NULL || iv_len <= 0 ||
	    ct_len < 0 || tag_len <= 0) {
		jwt_write_error(__cmd, "Error decoding JWE components");
		goto fail;
	}

	/* @rfc{7516,5.2} Build the AAD (ASCII(protected) for Compact, plus '.'
	 * BASE64URL(aad) when an "aad" member is present) and decrypt+verify. */
	if (jwe_build_aad(protected_b64, aad_b64, &aad, &aad_len, &aad_owned))
		goto oom; // LCOV_EXCL_LINE
	if (jwe_decrypt_content(enc, cek, cek_len, iv, iv_len, aad, aad_len,
				ct, ct_len, tag, tag_len, &pt, &pt_len)) {
		jwt_write_error(__cmd, "JWE authentication/decryption failed");
		goto fail;
	}

	/* Hand back a nil-terminated buffer for caller convenience. */
	out = jwt_malloc(pt_len + 1);
	if (out == NULL)
		goto oom; // LCOV_EXCL_LINE
	if (pt_len)
		memcpy(out, pt, pt_len);
	out[pt_len] = '\0';
	if (plaintext_len)
		*plaintext_len = pt_len;

	goto done;

	// LCOV_EXCL_START
oom:
	jwt_write_error(__cmd, "Error allocating memory");
	// LCOV_EXCL_STOP
fail:
	out = NULL;
done:
	if (aad_owned) {
		void *aad_free = (void *)(uintptr_t)aad;
		jwt_freemem(aad_free);
	}
	jwt_scrub_and_free(cek, cek_len);
	jwt_freemem(enckey);
	jwt_freemem(iv);
	jwt_freemem(ct);
	jwt_freemem(tag);
	jwt_scrub_and_free(pt, pt_len);

	return out;
}

/* @rfc{7516,5.2} Decrypt and authenticate a Compact Serialization JWE. */
static unsigned char *FUNC(decrypt_compact)(jwe_common_t *__cmd,
		struct jwe_recipient *recip, const char *token,
		size_t *plaintext_len)
{
	char_auto *dup = NULL;
	char *p_hdr, *p_ek, *p_iv, *p_ct, *p_tag, *rest;
	jwt_json_auto_t *hdr = NULL;
	char_auto *hdr_json = NULL;
	int hdr_dlen = 0;
	jwt_json_t *jalg, *jenc;
	jwe_key_alg_t alg;
	jwe_enc_t enc;
	size_t dup_len;

	dup_len = strlen(token) + 1;
	dup = jwt_malloc(dup_len);
	if (dup == NULL) {
		jwt_write_error(__cmd, "Error allocating memory"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}
	memcpy(dup, token, dup_len);

	/* @rfc{7516,5.2} Split exactly 5 parts (4 dots). */
	p_hdr = dup;
	p_ek = split_dot(p_hdr);
	p_iv = p_ek ? split_dot(p_ek) : NULL;
	p_ct = p_iv ? split_dot(p_iv) : NULL;
	p_tag = p_ct ? split_dot(p_ct) : NULL;
	rest = p_tag ? split_dot(p_tag) : NULL;

	if (p_tag == NULL || rest != NULL) {
		jwt_write_error(__cmd,
			"JWE must have exactly 5 parts (4 dots)");
		return NULL;
	}

	/* @rfc{7516,5.2} Parse the protected header and confirm alg/enc match
	 * what the application configured (algorithm allow-list). */
	hdr_json = jwt_base64uri_decode(p_hdr, &hdr_dlen);
	if (hdr_json == NULL || hdr_dlen <= 0) {
		jwt_write_error(__cmd, "Error decoding JWE header");
		return NULL;
	}
	hdr_json[hdr_dlen] = '\0';
	hdr = jwt_json_parse(hdr_json, 0, NULL);
	if (hdr == NULL) {
		jwt_write_error(__cmd, "Error parsing JWE header");
		return NULL;
	}

	/* A JWE protected header carries "enc"; its absence means this is not
	 * a JWE (e.g. a JWS was passed). The Compact Serialization also carries
	 * "alg" in the protected header. */
	jenc = jwt_json_obj_get(hdr, "enc");
	jalg = jwt_json_obj_get(hdr, "alg");
	if (jenc == NULL || !jwt_json_is_string(jenc) ||
	    jalg == NULL || !jwt_json_is_string(jalg)) {
		jwt_write_error(__cmd, "Not a JWE: missing alg/enc header");
		return NULL;
	}

	if (jwt_json_obj_get(hdr, "zip") != NULL) {
		jwt_write_error(__cmd, "JWE \"zip\" is not supported");
		return NULL;
	}

	alg = jwe_str_alg(jwt_json_str_val(jalg));
	enc = jwe_str_enc(jwt_json_str_val(jenc));
	if (alg != recip->key_alg || enc != __cmd->c.enc) {
		jwt_write_error(__cmd, "JWE alg/enc does not match expected");
		return NULL;
	}

	/* For Compact the AAD is just ASCII(protected) (no "aad" member) and the
	 * "epk" (if any) lives in the protected header. */
	return FUNC(recover_and_decrypt)(__cmd, recip, hdr, alg, enc, p_hdr,
					 NULL, p_ek, p_iv, p_ct, p_tag,
					 plaintext_len);
}

/* @rfc{7516,5.2} Decrypt and authenticate a Compact Serialization JWE. */
unsigned char *FUNC(decrypt)(jwe_common_t *__cmd, const char *token,
			     size_t *plaintext_len)
{
	struct jwe_recipient *recip;

	if (__cmd == NULL)
		return NULL;

	if (token == NULL || !strlen(token)) {
		jwt_write_error(__cmd, "Must pass a token");
		return NULL;
	}

	/* @rfc{7516,7.1} The checker is configured with one (alg, enc, key) via
	 * setkey, which populates the first recipient. */
	recip = jwe_recipient_first(&__cmd->c);
	if (recip == NULL || recip->key == NULL ||
	    recip->key_alg == JWE_ALG_NONE) {
		jwt_write_error(__cmd, "No key/algorithm set");
		return NULL;
	}

	return FUNC(decrypt_compact)(__cmd, recip, token, plaintext_len);
}

/* Get a required string member of @obj. Returns its value or NULL (setting an
 * error) if absent or not a string. Type-checked so json-c does not abort. */
static const char *FUNC(json_str_member)(jwe_common_t *__cmd, jwt_json_t *obj,
					 const char *name, int required)
{
	jwt_json_t *m = jwt_json_obj_get(obj, name);

	if (m == NULL) {
		if (required)
			jwt_write_error(__cmd, "JWE JSON missing \"%s\"", name);
		return NULL;
	}
	if (!jwt_json_is_string(m)) {
		jwt_write_error(__cmd, "JWE JSON \"%s\" is not a string", name);
		return NULL;
	}

	return jwt_json_str_val(m);
}

/* @rfc{7516,7.2} Decrypt a JSON Serialization (Flattened or single-recipient
 * General). The protected header is authenticated; the per-recipient header
 * supplies "alg" (and the ECDH-ES "epk"). Multi-recipient selection and full
 * header-disjointness enforcement are added in a later stage. */
static unsigned char *FUNC(decrypt_json)(jwe_common_t *__cmd,
		struct jwe_recipient *recip, const char *token,
		size_t *plaintext_len)
{
	jwt_json_auto_t *obj = NULL, *prot = NULL, *eff = NULL;
	char_auto *prot_json = NULL;
	jwt_json_t *recips, *rcp, *rhdr, *unprot, *jenc;
	const char *prot_b64, *iv_b64, *ct_b64, *tag_b64, *aad_b64, *ek_b64;
	const char *alg_str, *enc_str;
	int prot_dlen = 0;
	jwe_key_alg_t alg;
	jwe_enc_t enc;

	obj = jwt_json_parse(token, 0, NULL);
	if (obj == NULL) {
		jwt_write_error(__cmd, "Error parsing JWE JSON");
		return NULL;
	}

	/* @rfc{7516,7.2} "protected" is required for the algorithms we support
	 * (it carries "enc"). Decode and parse it; keep the verbatim b64 for the
	 * AAD. */
	prot_b64 = FUNC(json_str_member)(__cmd, obj, "protected", 1);
	if (prot_b64 == NULL)
		return NULL;
	prot_json = jwt_base64uri_decode(prot_b64, &prot_dlen);
	if (prot_json == NULL || prot_dlen <= 0) {
		jwt_write_error(__cmd, "Error decoding JWE protected header");
		return NULL;
	}
	prot_json[prot_dlen] = '\0';
	prot = jwt_json_parse(prot_json, 0, NULL);
	if (prot == NULL) {
		jwt_write_error(__cmd, "Error parsing JWE protected header");
		return NULL;
	}

	jenc = jwt_json_obj_get(prot, "enc");
	if (jenc == NULL || !jwt_json_is_string(jenc)) {
		jwt_write_error(__cmd, "Not a JWE: missing enc header");
		return NULL;
	}
	if (jwt_json_obj_get(prot, "zip") != NULL) {
		jwt_write_error(__cmd, "JWE \"zip\" is not supported");
		return NULL;
	}

	/* @rfc{7516,7.2.1} Locate the recipient. General form has a "recipients"
	 * array; Flattened hoists "header"/"encrypted_key" to the top level. The
	 * two forms are mutually exclusive. This stage decrypts a single
	 * recipient (the first); multi-recipient selection lands later. */
	recips = jwt_json_obj_get(obj, "recipients");
	if (recips != NULL) {
		if (jwt_json_obj_get(obj, "header") != NULL ||
		    jwt_json_obj_get(obj, "encrypted_key") != NULL) {
			jwt_write_error(__cmd,
				"JWE JSON has both General and Flattened members");
			return NULL;
		}
		if (!jwt_json_is_array(recips) || jwt_json_arr_size(recips) == 0) {
			jwt_write_error(__cmd,
				"JWE JSON \"recipients\" must be a non-empty array");
			return NULL;
		}
		rcp = jwt_json_arr_get(recips, 0);
		if (rcp == NULL) {
			jwt_write_error(__cmd, "JWE JSON recipient is invalid"); // LCOV_EXCL_LINE
			return NULL; // LCOV_EXCL_LINE
		}
		rhdr = jwt_json_obj_get(rcp, "header");
		ek_b64 = FUNC(json_str_member)(__cmd, rcp, "encrypted_key", 0);
		if (ek_b64 == NULL && jwt_json_obj_get(rcp, "encrypted_key"))
			return NULL;
	} else {
		rcp = NULL;
		rhdr = jwt_json_obj_get(obj, "header");
		ek_b64 = FUNC(json_str_member)(__cmd, obj, "encrypted_key", 0);
		if (ek_b64 == NULL && jwt_json_obj_get(obj, "encrypted_key"))
			return NULL;
	}

	/* @rfc{7516,7.2.1} The effective JOSE header is the union of the
	 * protected, shared-unprotected and per-recipient headers. (Strict
	 * disjointness enforcement is added in the multi-recipient stage; here a
	 * later source simply overrides an earlier one.) "alg" and "epk" are read
	 * from this union. */
	eff = jwt_json_clone(prot);
	if (eff == NULL)
		goto oom; // LCOV_EXCL_LINE
	unprot = jwt_json_obj_get(obj, "unprotected");
	if (unprot != NULL) {
		if (!jwt_json_is_object(unprot)) {
			jwt_write_error(__cmd,
				"JWE JSON \"unprotected\" is not an object");
			return NULL;
		}
		if (jwt_json_obj_merge(eff, unprot))
			goto oom; // LCOV_EXCL_LINE
	}
	if (rhdr != NULL) {
		if (!jwt_json_is_object(rhdr)) {
			jwt_write_error(__cmd,
				"JWE JSON recipient \"header\" is not an object");
			return NULL;
		}
		if (jwt_json_obj_merge(eff, rhdr))
			goto oom; // LCOV_EXCL_LINE
	}

	alg_str = FUNC(json_str_member)(__cmd, eff, "alg", 1);
	enc_str = jwt_json_str_val(jenc);
	if (alg_str == NULL)
		return NULL;
	alg = jwe_str_alg(alg_str);
	enc = jwe_str_enc(enc_str);
	if (alg != recip->key_alg || enc != __cmd->c.enc) {
		jwt_write_error(__cmd, "JWE alg/enc does not match expected");
		return NULL;
	}

	/* Required content members. */
	iv_b64 = FUNC(json_str_member)(__cmd, obj, "iv", 1);
	ct_b64 = FUNC(json_str_member)(__cmd, obj, "ciphertext", 1);
	tag_b64 = FUNC(json_str_member)(__cmd, obj, "tag", 1);
	if (iv_b64 == NULL || ct_b64 == NULL || tag_b64 == NULL)
		return NULL;

	/* Optional "aad" member: authenticated, and surfaced via get_aad. */
	aad_b64 = FUNC(json_str_member)(__cmd, obj, "aad", 0);
	if (aad_b64 == NULL && jwt_json_obj_get(obj, "aad"))
		return NULL;
	/* recovered_aad was already reset by decrypt_all; only repopulate it. */
	if (aad_b64 != NULL) {
		int raw_len = 0;
		unsigned char *raw = jwt_base64uri_decode(aad_b64, &raw_len);

		if (raw == NULL || raw_len < 0) {
			jwt_freemem(raw);
			jwt_write_error(__cmd, "Error decoding JWE aad");
			return NULL;
		}
		__cmd->c.recovered_aad = raw;
		__cmd->c.recovered_aad_len = (size_t)raw_len;
	}

	/* The ECDH-ES "epk" is read from the effective header. */
	return FUNC(recover_and_decrypt)(__cmd, recip, eff, alg, enc, prot_b64,
					 aad_b64, ek_b64, iv_b64, ct_b64,
					 tag_b64, plaintext_len);

	// LCOV_EXCL_START
oom:
	jwt_write_error(__cmd, "Error allocating memory");
	return NULL;
	// LCOV_EXCL_STOP
}

/* @rfc{7516,7} Decrypt a JWE in any serialization, auto-detecting compact vs
 * JSON: a token whose first non-space character is '{' is JSON. */
unsigned char *FUNC(decrypt_all)(jwe_common_t *__cmd, const char *token,
				 size_t *plaintext_len)
{
	struct jwe_recipient *recip;
	const char *p;

	if (__cmd == NULL)
		return NULL;

	if (token == NULL || !strlen(token)) {
		jwt_write_error(__cmd, "Must pass a token");
		return NULL;
	}

	recip = jwe_recipient_first(&__cmd->c);
	if (recip == NULL || recip->key == NULL ||
	    recip->key_alg == JWE_ALG_NONE) {
		jwt_write_error(__cmd, "No key/algorithm set");
		return NULL;
	}

	/* @rfc{7516,7.2.1} Reset any AAD recovered from a prior token before this
	 * decrypt, so get_aad() reflects only the current token regardless of
	 * serialization or an early failure. Only the JSON path repopulates it. */
	jwt_scrub_and_free(__cmd->c.recovered_aad, __cmd->c.recovered_aad_len);
	__cmd->c.recovered_aad = NULL;
	__cmd->c.recovered_aad_len = 0;

	for (p = token; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++)
		;

	if (*p == '{')
		return FUNC(decrypt_json)(__cmd, recip, token, plaintext_len);

	return FUNC(decrypt_compact)(__cmd, recip, token, plaintext_len);
}

/* @rfc{7516,7.2.1} Return the AAD recovered from the last JSON token. */
const unsigned char *FUNC(get_aad)(const jwe_common_t *__cmd, size_t *aad_len)
{
	if (__cmd == NULL)
		return NULL;

	if (aad_len)
		*aad_len = __cmd->c.recovered_aad_len;

	return __cmd->c.recovered_aad;
}
#endif
