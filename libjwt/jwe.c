/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

/* @rfc{7516,5.1} step 2: generate a random CEK of the length required by the
 * content encryption algorithm, using the active backend's CSPRNG. */
int jwe_generate_cek(jwe_enc_t enc, unsigned char **cek, size_t *cek_len)
{
	unsigned char *buf;
	size_t len;

	if (cek == NULL || cek_len == NULL)
		return 1; // LCOV_EXCL_LINE

	*cek = NULL;
	*cek_len = 0;

	len = jwe_enc_cek_len(enc);
	if (len == 0)
		return 1; // LCOV_EXCL_LINE

	if (jwt_ops->rng == NULL)
		return 1; // LCOV_EXCL_LINE

	buf = jwt_malloc(len);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE

	if (jwt_ops->rng(buf, len)) {
		// LCOV_EXCL_START
		jwt_scrub_and_free(buf, len);
		return 1;
		// LCOV_EXCL_STOP
	}

	*cek = buf;
	*cek_len = len;

	return 0;
}

/* @rfc{7518,4.4} Is this an AES Key Wrap key management algorithm? */
static int alg_is_aeskw(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_A128KW || alg == JWE_ALG_A192KW ||
	       alg == JWE_ALG_A256KW;
}

/* @rfc{7518,4.4} The KEK oct-key length that an AES-KW alg requires. */
static size_t aeskw_key_len(jwe_key_alg_t alg)
{
	switch (alg) {
	case JWE_ALG_A128KW:
		return 16;
	case JWE_ALG_A192KW:
		return 24;
	case JWE_ALG_A256KW:
		return 32;
	// LCOV_EXCL_START
	default:
		return 0;
	// LCOV_EXCL_STOP
	}
}

/* Wrap a freshly-generated CEK to the recipient for an AES-KW alg. */
int jwe_wrap_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		 const unsigned char *cek, size_t cek_len,
		 unsigned char **out, size_t *out_len)
{
	const unsigned char *k;
	size_t klen = 0;

	if (!alg_is_aeskw(alg))
		return 1; // LCOV_EXCL_LINE

	/* The KEK length must match the alg (A128KW needs a 128-bit key). */
	if (jwks_item_key_oct(key, &k, &klen) || klen != aeskw_key_len(alg))
		return 1;

	if (jwt_ops->wrap_aes_kw == NULL)
		return 1; // LCOV_EXCL_LINE

	return jwt_ops->wrap_aes_kw(key, cek, cek_len, out, out_len);
}

/* Unwrap the JWE Encrypted Key to recover the CEK for an AES-KW alg. */
int jwe_unwrap_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		   const unsigned char *in, size_t in_len,
		   unsigned char **cek, size_t *cek_len)
{
	const unsigned char *k;
	size_t klen = 0;

	if (!alg_is_aeskw(alg))
		return 1; // LCOV_EXCL_LINE

	if (jwks_item_key_oct(key, &k, &klen) || klen != aeskw_key_len(alg))
		return 1;

	if (jwt_ops->unwrap_aes_kw == NULL)
		return 1; // LCOV_EXCL_LINE

	return jwt_ops->unwrap_aes_kw(key, in, in_len, cek, cek_len);
}

/* @rfc{7518,4.3} Is this an RSAES-OAEP key management algorithm? */
static int alg_is_rsa(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_RSA_OAEP || alg == JWE_ALG_RSA_OAEP_256;
}

/* @rfc{7518,4.6} Is this an ECDH-ES key management algorithm? */
int jwe_alg_is_ecdh(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_ECDH_ES || alg == JWE_ALG_ECDH_ES_A128KW ||
	       alg == JWE_ALG_ECDH_ES_A192KW || alg == JWE_ALG_ECDH_ES_A256KW;
}

/* Is this ECDH-ES in Direct Key Agreement mode (the agreed key IS the CEK,
 * no wrapping, empty Encrypted Key)? */
int jwe_alg_is_ecdh_direct(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_ECDH_ES;
}

/* @rfc{7516,7.2.1} Does this algorithm dictate the CEK from the recipient key
 * (dir or ECDH-ES Direct)? Such an algorithm constrains the single shared CEK,
 * so it cannot be combined with other recipients. */
int jwe_alg_is_direct(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_DIR || jwe_alg_is_ecdh_direct(alg);
}

/* @rfc{7518,4.6} Run ECDH-ES agreement to derive the agreed key: the CEK in
 * Direct mode, or the KEK that wraps the CEK in +A*KW mode. On encrypt this
 * also writes "epk" into @hdr. */
int jwe_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc, const jwk_item_t *key,
		    int for_encrypt, jwt_json_t *hdr,
		    unsigned char **dk, size_t *dk_len)
{
	struct jwt_crypto_ops *ops = jwt_item_ops(key);

	if (ops == NULL || ops->ecdh_derive == NULL)
		return 1; // LCOV_EXCL_LINE
	return ops->ecdh_derive(alg, enc, key, for_encrypt, hdr, dk, dk_len);
}

/* @rfc{7518,4.4} AES Key Wrap / Unwrap with a raw KEK (the ECDH-ES agreed
 * key in +A*KW mode). Returns 0 on success. */
int jwe_aeskw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *cek, size_t cek_len,
		       unsigned char **out, size_t *out_len)
{
	if (jwt_ops->wrap_aes_kw_raw == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->wrap_aes_kw_raw(kek, kek_len, cek, cek_len, out, out_len);
}

int jwe_aeskw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **cek, size_t *cek_len)
{
	if (jwt_ops->unwrap_aes_kw_raw == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->unwrap_aes_kw_raw(kek, kek_len, in, in_len, cek, cek_len);
}

/* Encrypt the CEK to the recipient for a key management alg that wraps or
 * encrypts a generated CEK (A*KW or RSA-OAEP). Returns 0 on success. */
int jwe_encrypt_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		    const unsigned char *cek, size_t cek_len,
		    unsigned char **out, size_t *out_len)
{
	if (alg_is_aeskw(alg))
		return jwe_wrap_cek(alg, key, cek, cek_len, out, out_len);

	if (alg_is_rsa(alg)) {
		struct jwt_crypto_ops *ops = jwt_item_ops(key);

		if (ops == NULL || ops->encrypt_cek_rsa == NULL)
			return 1; // LCOV_EXCL_LINE
		return ops->encrypt_cek_rsa(alg, key, cek, cek_len,
					    out, out_len);
	}

	return 1; // LCOV_EXCL_LINE
}

/* Recover the CEK from the JWE Encrypted Key. Returns 0 on success. On any
 * failure the caller substitutes a random CEK (RFC 7516 11.5) rather than
 * surfacing the specific error. */
int jwe_decrypt_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		    const unsigned char *in, size_t in_len,
		    unsigned char **cek, size_t *cek_len)
{
	if (alg_is_aeskw(alg))
		return jwe_unwrap_cek(alg, key, in, in_len, cek, cek_len);

	if (alg_is_rsa(alg)) {
		struct jwt_crypto_ops *ops = jwt_item_ops(key);

		if (ops == NULL || ops->decrypt_cek_rsa == NULL)
			return 1; // LCOV_EXCL_LINE
		return ops->decrypt_cek_rsa(alg, key, in, in_len,
					    cek, cek_len);
	}

	return 1; // LCOV_EXCL_LINE
}

/* Is this a GCM content encryption algorithm? */
static int enc_is_gcm(jwe_enc_t enc)
{
	return enc == JWE_ENC_A128GCM || enc == JWE_ENC_A192GCM ||
	       enc == JWE_ENC_A256GCM;
}

/* Dispatch content encryption to the active backend for the given enc.
 * Returns 0 on success. */
int jwe_encrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len)
{
	if (enc_is_gcm(enc)) {
		if (jwt_ops->encrypt_aes_gcm == NULL)
			return 1; // LCOV_EXCL_LINE
		return jwt_ops->encrypt_aes_gcm(enc, cek, cek_len, iv, iv_len,
			aad, aad_len, pt, pt_len, ct, ct_len, tag, tag_len);
	}

	if (jwt_ops->encrypt_aes_cbc_hmac == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->encrypt_aes_cbc_hmac(enc, cek, cek_len, iv, iv_len,
		aad, aad_len, pt, pt_len, ct, ct_len, tag, tag_len);
}

/* Dispatch content decryption (with tag verification) to the active backend. */
int jwe_decrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len)
{
	/* Reject an IV whose length is not the exact size this "enc" requires.
	 * RFC 7518 5.3 fixes the GCM IV at 96 bits and 5.2 fixes the CBC-HMAC IV
	 * at 128 bits; the IV is attacker-controlled (base64url-decoded from the
	 * token) and the caller only checked iv_len > 0. The CBC backends already
	 * enforce 16 internally, but the GCM backends accepted any length and set
	 * it as the GCM IV. Gate both modes centrally so non-conformant IV lengths
	 * are rejected uniformly across all backends. */
	if (iv_len != jwe_enc_iv_len(enc))
		return 1;

	if (enc_is_gcm(enc)) {
		if (jwt_ops->decrypt_aes_gcm == NULL)
			return 1; // LCOV_EXCL_LINE
		return jwt_ops->decrypt_aes_gcm(enc, cek, cek_len, iv, iv_len,
			aad, aad_len, ct, ct_len, tag, tag_len, pt, pt_len);
	}

	if (jwt_ops->decrypt_aes_cbc_hmac == NULL)
		return 1; // LCOV_EXCL_LINE
	return jwt_ops->decrypt_aes_cbc_hmac(enc, cek, cek_len, iv, iv_len,
		aad, aad_len, ct, ct_len, tag, tag_len, pt, pt_len);
}

/* @rfc{7518,4.7} Is this an AES-GCM key-wrap algorithm? */
int jwe_alg_is_gcmkw(jwe_key_alg_t alg)
{
	return alg == JWE_ALG_A128GCMKW || alg == JWE_ALG_A192GCMKW ||
	       alg == JWE_ALG_A256GCMKW;
}

/* @rfc{7518,4.7} The KEK oct length a GCM-KW alg requires. */
static size_t gcmkw_kek_len(jwe_key_alg_t alg)
{
	switch (alg) {
	case JWE_ALG_A128GCMKW:
		return 16;
	case JWE_ALG_A192GCMKW:
		return 24;
	case JWE_ALG_A256GCMKW:
		return 32;
	// LCOV_EXCL_START
	default:
		return 0;
	// LCOV_EXCL_STOP
	}
}

/* The GCM content-encryption "enc" whose AES key size matches a GCM-KW alg, so
 * the existing GCM code can wrap/unwrap the CEK. */
static jwe_enc_t gcmkw_to_enc(jwe_key_alg_t alg)
{
	switch (alg) {
	case JWE_ALG_A128GCMKW:
		return JWE_ENC_A128GCM;
	case JWE_ALG_A192GCMKW:
		return JWE_ENC_A192GCM;
	case JWE_ALG_A256GCMKW:
		return JWE_ENC_A256GCM;
	// LCOV_EXCL_START
	default:
		return JWE_ENC_INVAL;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,4.7} AES-GCM key wrap: GCM-encrypt the CEK under the oct KEK with a
 * FRESH 96-bit IV and an empty AAD. The wrapped CEK is the Encrypted Key (@out);
 * the 96-bit IV and 128-bit tag are written base64url into @hdr as "iv"/"tag".
 * A fresh CSPRNG IV per wrap is mandatory (RFC 7518 8.7: nonce reuse under the
 * same KEK is a catastrophic GCM break) — the IV is generated here and is never
 * caller-supplied. Returns 0 on success. */
int jwe_gcmkw_wrap(jwe_key_alg_t alg, const jwk_item_t *key,
		   const unsigned char *cek, size_t cek_len,
		   jwt_json_t *hdr, unsigned char **out, size_t *out_len)
{
	jwe_enc_t enc = gcmkw_to_enc(alg);
	const unsigned char *k;
	unsigned char iv[12], *tag = NULL;
	char *iv_b64 = NULL, *tag_b64 = NULL;
	size_t klen = 0, tag_len = 0;
	int ret = 1;

	if (jwks_item_key_oct(key, &k, &klen) || klen != gcmkw_kek_len(alg))
		return 1;

	if (jwt_ops->rng == NULL || jwt_ops->rng(iv, sizeof(iv)))
		return 1; // LCOV_EXCL_LINE

	if (jwe_encrypt_content(enc, k, klen, iv, sizeof(iv), NULL, 0,
				cek, cek_len, out, out_len, &tag, &tag_len))
		goto out; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&iv_b64, (char *)iv, (int)sizeof(iv)) <= 0 ||
	    jwt_base64uri_encode(&tag_b64, (char *)tag, (int)tag_len) <= 0)
		goto out; // LCOV_EXCL_LINE

	if (jwt_json_obj_set(hdr, "iv", jwt_json_create_str(iv_b64)) ||
	    jwt_json_obj_set(hdr, "tag", jwt_json_create_str(tag_b64)))
		goto out; // LCOV_EXCL_LINE

	ret = 0;

out:
	jwt_freemem(tag);
	jwt_freemem(iv_b64);
	jwt_freemem(tag_b64);
	if (ret) {
		// LCOV_EXCL_START
		jwt_freemem(*out);
		*out_len = 0;
		// LCOV_EXCL_STOP
	}

	return ret;
}

/* @rfc{7518,4.7} AES-GCM key unwrap: read the "iv"/"tag" from @hdr and
 * GCM-decrypt the Encrypted Key under the oct KEK (empty AAD) to recover the
 * CEK. jwe_decrypt_content enforces the 96-bit IV and verifies the tag, so a
 * bad tag fails here; per RFC 7516 11.5 the caller then substitutes a random
 * CEK. Returns 0 on success. */
int jwe_gcmkw_unwrap(jwe_key_alg_t alg, const jwk_item_t *key, jwt_json_t *hdr,
		     const unsigned char *in, size_t in_len,
		     unsigned char **cek, size_t *cek_len)
{
	jwe_enc_t enc = gcmkw_to_enc(alg);
	jwt_json_t *jiv, *jtag;
	const unsigned char *k;
	unsigned char *iv = NULL, *tag = NULL;
	size_t klen = 0;
	int iv_len = 0, tag_len = 0, ret = 1;

	if (jwks_item_key_oct(key, &k, &klen) || klen != gcmkw_kek_len(alg))
		return 1;

	jiv = jwt_json_obj_get(hdr, "iv");
	jtag = jwt_json_obj_get(hdr, "tag");
	if (jiv == NULL || !jwt_json_is_string(jiv) ||
	    jtag == NULL || !jwt_json_is_string(jtag))
		return 1;

	iv = jwt_base64uri_decode(jwt_json_str_val(jiv), &iv_len);
	tag = jwt_base64uri_decode(jwt_json_str_val(jtag), &tag_len);
	if (iv == NULL || tag == NULL || iv_len <= 0 || tag_len <= 0)
		goto out;

	if (jwe_decrypt_content(enc, k, klen, iv, iv_len, NULL, 0,
				in, in_len, tag, tag_len, cek, cek_len))
		goto out;

	ret = 0;

out:
	jwt_freemem(iv);
	jwt_freemem(tag);

	return ret;
}

/* @rfc{7516,11.4} @rfc{7517,4.2,4.3} Gate a JWK against a JWE key management
 * algorithm. */
const char *jwe_key_usage_check(const jwk_item_t *key, jwe_key_alg_t alg,
				int for_encrypt)
{
	jwk_key_type_t need = jwe_alg_required_kty(alg);

	/* Callers (setkey) already reject a NULL key; this is defensive. */
	if (key == NULL)
		return "JWE requires a key"; // LCOV_EXCL_LINE

	if (need == JWK_KEY_TYPE_NONE)
		return "Unknown JWE key management algorithm"; // LCOV_EXCL_LINE

	/* @rfc{7518,4.6} ECDH-ES accepts an EC key (P-256/384/521) or an OKP
	 * key on an X-curve (X25519/X448). An OKP Ed-curve key is for signing
	 * only and must be rejected. */
	if (jwe_alg_is_ecdh(alg)) {
		jwk_key_type_t kty = jwks_item_kty(key);
		const char *crv = jwks_item_curve(key);

		if (kty == JWK_KEY_TYPE_EC) {
			/* Any supported EC curve is fine; the derive validates
			 * the specific curve. */
		} else if (kty == JWK_KEY_TYPE_OKP && crv != NULL &&
			   (!strcmp(crv, "X25519") || !strcmp(crv, "X448"))) {
			/* OKP X-curve: usable for key agreement. */
		} else {
			return "Key type/curve does not match ECDH-ES";
		}
	} else if (jwks_item_kty(key) != need) {
		/* The key's actual type must match what the alg requires. This
		 * is the authoritative gate and ignores optional JWK hints. */
		return "Key type does not match JWE algorithm";
	}

	/* @rfc{7517,4.2} If "use" is set, it must be "enc" for JWE; a key
	 * marked "sig" must never be used for encryption. */
	if (jwks_item_use(key) == JWK_PUB_KEY_USE_SIG)
		return "Key marked for signing cannot be used for JWE";

	/* @rfc{7517,4.3} If "key_ops" is present, it must permit the operation
	 * we are about to perform. dir/A*KW use (un)wrapKey; RSA-OAEP uses
	 * (en|de)crypt. If no key_ops are declared, this check is skipped. */
	if (jwks_item_key_ops(key) != JWK_KEY_OP_NONE) {
		jwk_key_op_t ops = jwks_item_key_ops(key);
		jwk_key_op_t want;

		switch (alg) {
		case JWE_ALG_DIR:
		case JWE_ALG_A128KW:
		case JWE_ALG_A192KW:
		case JWE_ALG_A256KW:
		case JWE_ALG_A128GCMKW:
		case JWE_ALG_A192GCMKW:
		case JWE_ALG_A256GCMKW:
			want = for_encrypt ? JWK_KEY_OP_WRAP : JWK_KEY_OP_UNWRAP;
			break;
		case JWE_ALG_RSA_OAEP:
		case JWE_ALG_RSA_OAEP_256:
			want = for_encrypt ? JWK_KEY_OP_ENCRYPT
					   : JWK_KEY_OP_DECRYPT;
			break;
		case JWE_ALG_ECDH_ES:
		case JWE_ALG_ECDH_ES_A128KW:
		case JWE_ALG_ECDH_ES_A192KW:
		case JWE_ALG_ECDH_ES_A256KW:
			/* Key agreement derives a key from the static key. */
			want = JWK_KEY_OP_DERIVE_KEY;
			break;
		// LCOV_EXCL_START
		default:
			return "Unknown JWE key management algorithm";
		// LCOV_EXCL_STOP
		}

		if (!(ops & want))
			return "Key does not permit the required JWE operation";
	}

	return NULL;
}

/* @rfc{7516,5.1} step 14 See jwt-private.h for the contract. The base AAD is
 * ASCII(Encoded Protected Header); a present JWE "aad" member adds '.' plus its
 * base64url. The no-aad case aliases @protected_b64 with zero allocation, so
 * the Compact Serialization keeps producing byte-identical AAD. */
int jwe_build_aad(const char *protected_b64, const char *aad_b64,
		  const unsigned char **aad, size_t *aad_len, int *owned)
{
	size_t plen, alen;
	char *buf;

	*owned = 0;

	if (aad_b64 == NULL) {
		*aad = (const unsigned char *)protected_b64;
		*aad_len = strlen(protected_b64);
		return 0;
	}

	plen = strlen(protected_b64);
	alen = strlen(aad_b64);
	buf = jwt_malloc(plen + 1 + alen + 1);
	if (buf == NULL)
		return 1; // LCOV_EXCL_LINE

	memcpy(buf, protected_b64, plen);
	buf[plen] = '.';
	memcpy(buf + plen + 1, aad_b64, alen);
	buf[plen + 1 + alen] = '\0';

	*aad = (const unsigned char *)buf;
	*aad_len = plen + 1 + alen;
	*owned = 1;

	return 0;
}

/* @rfc{7516,7.2.1} Return the first recipient, or NULL if the list is empty.
 * The Compact and Flattened serializations only ever have this one; the
 * General serialization iterates the list directly. */
struct jwe_recipient *jwe_recipient_first(struct jwe_common *cmd)
{
	if (cmd == NULL || cmd->recipients.next == &cmd->recipients)
		return NULL;

	return list_first_entry(&cmd->recipients, struct jwe_recipient, node);
}

/* Allocate and tail-append an empty recipient. Returns NULL on OOM. */
struct jwe_recipient *jwe_recipient_append(struct jwe_common *cmd)
{
	struct jwe_recipient *r;

	if (cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	r = jwt_malloc(sizeof(*r));
	if (r == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(r, 0, sizeof(*r));
	list_add_tail(&r->node, &cmd->recipients);
	cmd->n_recipients++;

	return r;
}

/* Return the first recipient, creating an empty one if the list is empty. Used
 * by the legacy single-key setkey path so repeated setkey() calls update one
 * recipient rather than appending. */
struct jwe_recipient *jwe_recipient_first_or_add(struct jwe_common *cmd)
{
	struct jwe_recipient *r;

	if (cmd == NULL)
		return NULL; // LCOV_EXCL_LINE

	r = jwe_recipient_first(cmd);
	if (r != NULL)
		return r;

	return jwe_recipient_append(cmd);
}

/* Free a single recipient and the members it owns. Does not unlink it; the
 * caller (FUNC(free)) drains the whole list. */
void jwe_recipient_free(struct jwe_recipient *r)
{
	if (r == NULL)
		return; // LCOV_EXCL_LINE

	jwt_scrub_and_free(r->enckey, r->enckey_len);
	jwt_freemem(r->apu);
	jwt_freemem(r->apv);
	jwt_json_release(r->header);
	jwt_freemem(r);
}
