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

#ifdef JWE_BUILDER
/* @rfc{7516,5.1} Encrypt @plaintext into a Compact Serialization JWE. This
 * stage implements the dir + AES-GCM path. */
char *FUNC(generate)(jwe_common_t *__cmd, const unsigned char *plaintext,
		     size_t plaintext_len)
{
	jwt_json_auto_t *hdr = NULL;
	char_auto *hdr_json = NULL, *hdr_b64 = NULL, *ek_b64 = NULL;
	char_auto *iv_b64 = NULL, *ct_b64 = NULL, *tag_b64 = NULL;
	unsigned char *cek = NULL, *iv = NULL, *ct = NULL, *tag = NULL;
	unsigned char *enckey = NULL;
	size_t cek_len = 0, iv_len, ct_len = 0, tag_len = 0, enckey_len = 0;
	const unsigned char *k;
	char *out = NULL;
	int hdr_len, ret;

	if (__cmd == NULL)
		return NULL;

	if (__cmd->c.key == NULL || __cmd->c.key_alg == JWE_ALG_NONE) {
		jwt_write_error(__cmd, "No key/algorithm set");
		return NULL;
	}

	if (plaintext == NULL && plaintext_len) {
		jwt_write_error(__cmd, "No plaintext given");
		return NULL;
	}

	/* @rfc{7516,5.1} step 12-13: build and encode the protected header. */
	hdr = jwt_json_create();
	if (hdr == NULL)
		goto oom; // LCOV_EXCL_LINE
	if (jwt_json_obj_set(hdr, "alg",
			     jwt_json_create_str(jwe_alg_str(__cmd->c.key_alg))) ||
	    jwt_json_obj_set(hdr, "enc",
			     jwt_json_create_str(jwe_enc_str(__cmd->c.enc)))) {
		jwt_write_error(__cmd, "Error building JWE header"); // LCOV_EXCL_LINE
		return NULL; // LCOV_EXCL_LINE
	}

	/* @rfc{7518,4.6} ECDH-ES (Direct): derive the CEK and add the "epk"
	 * to the header BEFORE it is serialized, since the header bytes are
	 * the AAD. The Encrypted Key stays empty (like dir). */
	if (jwe_alg_is_ecdh(__cmd->c.key_alg)) {
		/* @rfc{7518,4.6} Derive the agreed key and emit "epk" while the
		 * header object can still be modified. For Direct mode the
		 * agreed key is the CEK; for +A*KW it is the KEK. */
		unsigned char *agreed = NULL;
		size_t agreed_len = 0;

		if (jwe_ecdh_derive(__cmd->c.key_alg, __cmd->c.enc,
				    __cmd->c.key, 1, hdr, &agreed, &agreed_len)) {
			jwt_write_error(__cmd, "ECDH-ES key agreement failed");
			return NULL;
		}

		if (jwe_alg_is_ecdh_direct(__cmd->c.key_alg)) {
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
	if (jwe_alg_is_ecdh(__cmd->c.key_alg)) {
		/* ECDH-ES: the CEK (Direct) or CEK+Encrypted Key (+A*KW) was
		 * already produced above, before the header was serialized. */
	} else if (__cmd->c.key_alg == JWE_ALG_DIR) {
		/* dir: the CEK is the shared symmetric key; Encrypted Key is
		 * empty. */
		size_t need = jwe_enc_cek_len(__cmd->c.enc);

		ret = jwks_item_key_oct(__cmd->c.key, &k, &cek_len);
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
		if (jwe_encrypt_cek(__cmd->c.key_alg, __cmd->c.key, cek, cek_len,
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

	/* @rfc{7516,5.1} step 14-15: AAD is ASCII(Encoded Protected Header);
	 * encrypt the content. */
	ret = jwe_encrypt_content(__cmd->c.enc, cek, cek_len, iv, iv_len,
				  (const unsigned char *)hdr_b64,
				  strlen(hdr_b64), plaintext, plaintext_len,
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

	/* @rfc{7516,7.1} Assemble: header.encrypted_key.iv.ct.tag. The
	 * Encrypted Key segment is empty for dir and the wrapped key for A*KW.
	 * Length is the five parts plus 4 dots and a nil. */
	{
		const char *ek = ek_b64 ? ek_b64 : "";

		out = jwt_malloc(strlen(hdr_b64) + strlen(ek) + strlen(iv_b64) +
				 strlen(ct_b64) + strlen(tag_b64) + 5);
		if (out == NULL)
			goto oom; // LCOV_EXCL_LINE
		sprintf(out, "%s.%s.%s.%s.%s", hdr_b64, ek, iv_b64, ct_b64,
			tag_b64);
	}

	goto done;

	// LCOV_EXCL_START
oom:
	jwt_write_error(__cmd, "Error allocating memory");
	// LCOV_EXCL_STOP
fail:
	out = NULL;
done:
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

/* @rfc{7516,5.2} Decrypt and authenticate a Compact Serialization JWE. This
 * stage implements the dir + AES-GCM path. */
unsigned char *FUNC(decrypt)(jwe_common_t *__cmd, const char *token,
			     size_t *plaintext_len)
{
	char_auto *dup = NULL;
	char *p_hdr, *p_ek, *p_iv, *p_ct, *p_tag, *rest;
	jwt_json_auto_t *hdr = NULL;
	char_auto *hdr_json = NULL;
	unsigned char *cek = NULL, *iv = NULL, *ct = NULL, *tag = NULL;
	unsigned char *pt = NULL, *out = NULL, *enckey = NULL;
	int iv_len = 0, ct_len = 0, tag_len = 0, hdr_dlen = 0, ek_len = 0;
	size_t cek_len = 0, pt_len = 0;
	const unsigned char *k;
	jwt_json_t *jalg, *jenc;
	jwe_key_alg_t alg;
	jwe_enc_t enc;
	size_t dup_len;

	if (__cmd == NULL)
		return NULL;

	if (token == NULL || !strlen(token)) {
		jwt_write_error(__cmd, "Must pass a token");
		return NULL;
	}

	if (__cmd->c.key == NULL || __cmd->c.key_alg == JWE_ALG_NONE) {
		jwt_write_error(__cmd, "No key/algorithm set");
		return NULL;
	}

	dup_len = strlen(token) + 1;
	dup = jwt_malloc(dup_len);
	if (dup == NULL)
		goto oom; // LCOV_EXCL_LINE
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
	 * a JWE (e.g. a JWS was passed). */
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
	if (alg != __cmd->c.key_alg || enc != __cmd->c.enc) {
		jwt_write_error(__cmd, "JWE alg/enc does not match expected");
		return NULL;
	}

	/* @rfc{7516,5.2} CEK per the key management algorithm. */
	if (jwe_alg_is_ecdh(alg)) {
		/* @rfc{7518,4.6} Derive the agreed key from the recipient
		 * private key and the header's "epk". */
		unsigned char *agreed = NULL;
		size_t agreed_len = 0, need = jwe_enc_cek_len(enc);

		if (jwe_alg_is_ecdh_direct(alg) && *p_ek != '\0') {
			jwt_write_error(__cmd,
				"ECDH-ES (Direct) must have an empty Encrypted Key");
			return NULL;
		}
		if (!jwe_alg_is_ecdh_direct(alg) && *p_ek == '\0') {
			jwt_write_error(__cmd,
				"ECDH-ES+A*KW requires an Encrypted Key");
			return NULL;
		}

		/* A failed agreement (bad/missing epk, curve mismatch) is a
		 * structural error, not a key-recovery oracle. */
		if (jwe_ecdh_derive(alg, enc, __cmd->c.key, 0, hdr,
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

			enckey = jwt_base64uri_decode(p_ek, &ek_len);
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

		if (*p_ek != '\0') {
			jwt_write_error(__cmd,
				"dir must have an empty Encrypted Key");
			return NULL;
		}
		if (jwks_item_key_oct(__cmd->c.key, &k, &cek_len) ||
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

		if (*p_ek == '\0') {
			jwt_write_error(__cmd,
				"Key management requires an Encrypted Key");
			return NULL;
		}

		enckey = jwt_base64uri_decode(p_ek, &ek_len);
		if (enckey == NULL || ek_len <= 0)
			bad = 1;
		else if (jwe_decrypt_cek(alg, __cmd->c.key, enckey, ek_len,
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
	iv = jwt_base64uri_decode(p_iv, &iv_len);
	ct = jwt_base64uri_decode(p_ct, &ct_len);
	tag = jwt_base64uri_decode(p_tag, &tag_len);
	if (iv == NULL || ct == NULL || tag == NULL || iv_len <= 0 ||
	    ct_len < 0 || tag_len <= 0) {
		jwt_write_error(__cmd, "Error decoding JWE components");
		goto fail;
	}

	/* @rfc{7516,5.2} AAD is ASCII(Encoded Protected Header) = the received
	 * header bytes verbatim. Decrypt + verify the tag. */
	if (jwe_decrypt_content(enc, cek, cek_len, iv, iv_len,
				(const unsigned char *)p_hdr, strlen(p_hdr),
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
	jwt_scrub_and_free(cek, cek_len);
	jwt_freemem(enckey);
	jwt_freemem(iv);
	jwt_freemem(ct);
	jwt_freemem(tag);
	jwt_scrub_and_free(pt, pt_len);

	return out;
}
#endif
