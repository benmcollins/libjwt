/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_PRIVATE_H
#define JWT_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jwt-json-ops.h"
#include <time.h>
#include <stdarg.h>
#include <stddef.h>
#include <limits.h>
#ifdef HAVE_OPENSSL
/* Only the OpenSSL backend needs this, and those files include it directly.
 * Kept here under HAVE_OPENSSL so OpenSSL builds are unchanged; non-OpenSSL
 * builds must not depend on any OpenSSL header. */
#include <openssl/crypto.h>
#endif

#include "ll.h"

#ifndef ARRAY_SIZE
#  ifdef __GNUC__
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]) + \
	__builtin_types_compatible_p(typeof(__arr), typeof(&(__arr)[0])) * 0)
#  else
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]))
#  endif
#endif

#define JWT_CONFIG_DECLARE(__name) \
	jwt_config_t __name = { NULL, JWT_ALG_NONE, NULL}

#define JWT_ERR_LEN 256

JWT_NO_EXPORT
extern struct jwt_crypto_ops *jwt_ops;

/* The crypto ops to use for operations on @item. A jwk_item is bound to the
 * backend that parsed it (item->provider); route key operations through that
 * backend regardless of the active jwt_ops. Cross-compatible keys (oct, i.e.
 * JWT_CRYPTO_OPS_ANY) and a NULL/error item use the active ops. Returns NULL
 * only if the origin backend is not compiled into this build. */
JWT_NO_EXPORT
struct jwt_crypto_ops *jwt_item_ops(const jwk_item_t *item);

/* This can be used on anything with an error and error_msg field */
#define jwt_write_error(__obj, __fmt, __args...)	\
({							\
	if (!strlen((__obj)->error_msg))		\
		snprintf((__obj)->error_msg,		\
			 sizeof((__obj)->error_msg),	\
		 __fmt, ##__args);			\
	(__obj)->error = 1;				\
})

#define jwt_copy_error(__dst, __src)				\
({								\
	strncpy((__dst)->error_msg, (__src)->error_msg,		\
		sizeof((__dst)->error_msg) - 1);		\
	(__dst)->error_msg[sizeof((__dst)->error_msg) - 1] = '\0';	\
	(__dst)->error = (__src)->error;			\
})

/******************************/

struct jwt_common {
	jwt_alg_t alg;
	const jwk_item_t *key;
	jwt_json_t *payload;
	jwt_json_t *headers;
	jwt_claims_t claims;
	jwt_callback_t cb;
	void *cb_ctx;

	/* @rfc{7519,4.1.7} jti (JWT ID) callbacks. jti_gen is used by the
	 * builder to produce an id; jti_check is used by the checker to
	 * validate/consume one. jti_ctx is passed to whichever is set. */
	jwt_jti_gen_cb_t jti_gen;
	jwt_jti_check_cb_t jti_check;
	void *jti_ctx;

	/* NULL-terminated list of "crit" header parameter names that the
	 * application understands. Only used by the checker. */
	char **understood;

	/* For builder, this is offset into the future.
	 * For checker, this is the leeway.
	 * Both are in seconds. */
	time_t exp;
	time_t nbf;

	/* --- @rfc{7515,7.2} JSON Serialization (multi-signature) ---
	 * The single-signature Compact path uses .alg/.key above and an empty
	 * list, keeping its behavior byte-identical. The signature list is
	 * materialized by jwt_builder_setkey()/add_signature() (builder) or the
	 * JSON parse (checker); it is iterated only for the JSON serializations. */
	jwt_serialization_t format;	/* builder: emit form; default COMPACT (0) */
	ll_t signatures;		/* list of struct jwt_signature		*/
	int n_signatures;

	/* checker: a borrowed multi-key set (JWKS) and the multi-signature
	 * verification policy. NULL keyring => the single .key above is used. */
	const jwk_set_t *keyring;
	jwt_verify_policy_t policy;
	unsigned int last_sig_count;	/* signatures in the last JSON token	*/

	/* --- @rfc{7797} Unencoded payload / detached payload ---
	 * An opaque payload set via jwt_builder_setpayload() (mutually exclusive
	 * with JSON claims); signed as-is. @b64 (default 1) selects base64url vs
	 * the RFC 7797 unencoded ("b64":false) signing input; @detached omits the
	 * payload from the output (supplied out-of-band on verify). */
	unsigned char *payload_raw;
	size_t payload_raw_len;
	int b64;
	int detached;

	/* --- @rfc{8725} Checker ergonomics ---
	 * @expected_typ: if set, the token's "typ" must match it (case-insensitive,
	 * optional "application/" prefix). @alg_allowlist: if non-empty, the token's
	 * "alg" must be one of these (checked before the signature). */
	char *expected_typ;
	jwt_alg_t *alg_allowlist;
	size_t n_alg_allowlist;
};

struct jwt_builder {
	struct jwt_common c;
	int error;
	char error_msg[JWT_ERR_LEN];
};

struct jwt_checker {
	struct jwt_common c;
	int error;
	char error_msg[JWT_ERR_LEN];
};

/* @rfc{7515,7.2.1} One JWS signature: its own "alg" and PROTECTED header (the
 * exact bytes it signs over), an optional per-signature UNPROTECTED "header"
 * (JSON serializations only), the signing key (builder) or matched key
 * (checker), and the verbatim base64url protected header + signature. Linked
 * via ll.h: a Compact/Flattened JWS is a one-element list, General is N.
 * Owned by the enclosing struct jwt_common. */
struct jwt_signature {
	ll_t node;
	jwt_alg_t alg;		/* this signature's algorithm			*/
	const jwk_item_t *key;	/* builder: signing key; checker: matched key	*/
	jwt_json_t *protected;	/* per-signature protected header (builder)	*/
	jwt_json_t *header;	/* optional per-signature unprotected header	*/
	char *protected_b64;	/* VERBATIM base64url(protected); the signing	*/
				/* input reuses these bytes, never re-encoded	*/
	char *sig_b64;		/* base64url(signature)				*/
	int verified;		/* checker: 1 if this signature verified	*/
};

/******************************/

/* @rfc{7516,7.2.1} A single JWE recipient: its own key management alg, key,
 * optional ECDH-ES partyinfo, optional per-recipient (unprotected) header, and
 * the JWE Encrypted Key produced for it. Linked via ll.h (like jwk_set), so a
 * Compact / Flattened JWE is just a one-element list and the General JSON
 * Serialization is a list of N. Owned by the enclosing struct jwe_common. */
struct jwe_recipient {
	ll_t node;
	jwe_key_alg_t key_alg;	/* @rfc{7516,4.1.1} "alg" key management	*/
	const jwk_item_t *key;	/* Recipient key used for key management		*/

	/* @rfc{7518,4.6.2} Optional ECDH-ES PartyUInfo/PartyVInfo, stored as
	 * the base64url strings emitted in the "apu"/"apv" headers. */
	char *apu;
	char *apv;

	/* @rfc{7516,7.2.1} Optional per-recipient unprotected header. For the
	 * JSON serializations this also carries ECDH-ES "epk"/"apu"/"apv". */
	jwt_json_t *header;

	unsigned char *enckey;	/* JWE Encrypted Key (wrapped CEK)		*/
	size_t enckey_len;
};

/* JWE is kept deliberately separate from JWS/JWT. A JWE is structurally and
 * cryptographically different (5 parts, "alg"+"enc", a CEK), so it gets its
 * own common struct rather than overloading struct jwt_common. */
struct jwe_common {
	jwe_enc_t enc;		/* @rfc{7516,4.1.2} "enc" content encryption	*/
	jwt_json_t *payload;	/* Claims/plaintext to encrypt (builder)	*/
	jwt_json_t *headers;	/* @rfc{7516,7.2.1} Protected header		*/
	jwt_json_t *unprotected;/* @rfc{7516,7.2.1} Shared unprotected header	*/
	jwt_callback_t cb;
	void *cb_ctx;

	/* @rfc{7516,7.2.1} Recipients. setkey()/set_partyinfo() manage the
	 * first element; add_recipient() appends further ones. A Compact or
	 * Flattened JWE has exactly one. */
	ll_t recipients;
	int n_recipients;

	/* @rfc{7516,4.1.4} Serialization to emit (builder). */
	jwe_serialization_t format;

	/* @rfc{7518,4.8} PBES2 iteration count for the builder; 0 = the library
	 * default. Set via jwe_builder_setpbes2(). */
	unsigned int pbes2_p2c;

	/* @rfc{7516,5.1} step 14 The application-supplied JWE AAD (the "aad"
	 * member of the JSON serializations). @aad_b64 is its base64url form,
	 * which is also what is concatenated into the AEAD AAD. */
	unsigned char *aad;	/* Raw AAD provided by the builder caller	*/
	size_t aad_len;
	char *aad_b64;

	/* The shared JWE components (one CEK / IV / ciphertext / tag per token,
	 * regardless of recipient count). Populated during encrypt (builder) or
	 * decrypt (checker). Owned by this struct. */
	unsigned char *cek;	/* Content Encryption Key			*/
	size_t cek_len;
	unsigned char *iv;	/* JWE Initialization Vector			*/
	size_t iv_len;
	unsigned char *ct;	/* JWE Ciphertext				*/
	size_t ct_len;
	unsigned char *tag;	/* JWE Authentication Tag			*/
	size_t tag_len;

	/* @rfc{7516,7.2.1} The application AAD recovered by the checker from a
	 * JSON serialization's "aad" member, handed back via get_aad(). */
	unsigned char *recovered_aad;
	size_t recovered_aad_len;
};

struct jwe_builder {
	struct jwe_common c;
	int error;
	char error_msg[JWT_ERR_LEN];
};

struct jwe_checker {
	struct jwe_common c;
	int error;
	char error_msg[JWT_ERR_LEN];
};

/*****************************/

struct jwt {
	const jwk_item_t *key;
	jwt_json_t *claims;
	jwt_json_t *headers;
	jwt_alg_t alg;
	int error;
	char error_msg[JWT_ERR_LEN];

	/* @rfc{7797} An opaque payload (instead of JSON @claims), and the b64 /
	 * detached flags, threaded from the builder/checker into encode/verify.
	 * @payload_raw is borrowed (owned by jwt_common or the caller). */
	const unsigned char *payload_raw;
	size_t payload_raw_len;
	int b64;
	int detached;

	union {
		struct jwt_checker *checker;
		struct jwt_builder *builder;
	};
};

struct jwk_set {
	ll_t head;
	int error;
	char error_msg[JWT_ERR_LEN];
};

/**
 * This data structure is produced by importing a JWK or JWKS into a
 * @ref jwk_set_t object. Generally, you would not change any values here
 * and only use this to probe the internal parser and possibly to
 * decide whether a key applies to certain jwt_t for verification
 * or signing.
 *
 * If the jwk_item_t.pem field is not NULL, then it contains  a nil terminated
 * string of the key. The underlying crypto algorithm may or may not support
 * this. It's provided as a convenience.
 */
struct jwk_item {
	ll_t node;
	char *pem;		/**< If not NULL, contains PEM string of this key	*/
	jwt_crypto_provider_t provider;	/**< Crypto provider that owns this key		*/
	union {
		void *provider_data;	/**< Internal data used by the provider		*/
		struct {
			void *key;	/**< Used for HMAC key material			*/
			size_t len;	/**< Length of HMAC key material		*/
		} oct;
	};
	int is_private_key;	/**< Whether this is a public or private key		*/
	char curve[256];	/**< Curve name of an ``"EC"`` or ``"OKP"`` key		*/
	size_t bits;		/**< The number of bits in the key (may be 0)		*/
	int error;		/**< There was an error parsing this key (unusable)	*/
	char error_msg[JWT_ERR_LEN];/**< Descriptive message for @ref jwk_item_t.error	*/
	jwk_key_type_t kty;	/**< @rfc{7517,4.1} The key type of this key		*/
	jwk_pub_key_use_t use;	/**< @rfc{7517,4.2} How this key can be used		*/
	jwk_key_op_t key_ops;	/**< @rfc{7517,4.3} Key operations supported		*/
	jwt_alg_t alg;		/**< @rfc{7517,4.4} JWA Algorithm supported		*/
	char *kid;		/**< @rfc{7517,4.5} Key ID				*/
	jwt_json_t *json;	/**< The jwt_json_t for this key			*/
};

/* Crypto operations */
/* The largest number of base64url members any single key contributes to a JWK:
 * an RSA private key has n,e,d,p,q,dp,dq,qi = 8. */
#define JWK_EXPORT_MAX_PARAMS 8

/* One JWK member carrying raw key material (big-endian for integers, raw octets
 * for OKP) to be base64url-encoded by the common jwt_key2jwk() code. */
struct jwk_export_param {
	const char *name;	/* JWK member name: "n","e","d","p","q","dp","dq","qi","x","y" */
	unsigned char *data;	/* heap (jwt_malloc); freed and scrubbed by the common code */
	size_t len;
};

/* Neutral, crypto-free representation of a parsed native key. The active
 * backend's key2jwk_params op fills this from a PEM/DER blob; the common
 * jwt_key2jwk() (jwk-export.c) turns it into a JWK JSON object. This is the
 * inverse of the process_* JWK-parsing ops. */
typedef struct {
	jwk_key_type_t kty;	/* JWK_KEY_TYPE_RSA / _EC / _OKP			*/
	int is_private;		/* 1 if private material was extracted		*/
	char crv[256];		/* curve name (EC/OKP), empty if not applicable	*/
	char alg[32];		/* suggested "alg" value, empty if none		*/
	struct jwk_export_param params[JWK_EXPORT_MAX_PARAMS];
	int nparams;
} jwk_export_t;

struct jwt_crypto_ops {
	const char *name;
	jwt_crypto_provider_t provider;

	/* Signing/Verifying */
	int (*sign_sha_hmac)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	/* Verifying hmac is basically signing the current token and cmparing
	 * the signatures. */
	int (*sign_sha_pem)(jwt_t *jwt, char **out, unsigned int *len,
		const char *str, unsigned int str_len);
	int (*verify_sha_pem)(jwt_t *jwt, const char *head,
		unsigned int head_len, unsigned char *sig,
		int sig_len);

	/* Parsing a JWK to prepare it for use */
	int jwk_implemented;
	int (*process_eddsa)(jwt_json_t *jwk, jwk_item_t *item);
	int (*process_rsa)(jwt_json_t *jwk, jwk_item_t *item);
	int (*process_ec)(jwt_json_t *jwk, jwk_item_t *item);
	/* ML-DSA (AKP) JWK parsing; NULL on backends without ML-DSA support
	 * (the jwks.c kty dispatch null-guards this and fails cleanly). */
	int (*process_mldsa)(jwt_json_t *jwk, jwk_item_t *item);
	void (*process_item_free)(jwk_item_t *item);

	/* Inverse of the process_* ops: parse a native key (PEM or DER) and
	 * extract its raw components into the neutral jwk_export_t. The common
	 * jwt_key2jwk() then base64url-encodes them into a JWK. Returns 0 on
	 * success (out filled), or non-zero if the input is not a parseable
	 * asymmetric key (the common code then tries the HMAC fallback).
	 * Implemented natively by each backend; NULL if a backend cannot convert
	 * native keys at all. */
	int (*key2jwk_params)(const char *key, size_t len, jwk_export_t *out);

	/* Generate a fresh ASYMMETRIC key (EC/RSA/RSA-PSS/OKP/AKP) of type @kty
	 * with the geometry in @param and the discriminator @alg, emitting an
	 * unencrypted PKCS#8 private-key PEM into *@pem_out (jwt_malloc'd; the
	 * common jwks_generate() scrubs+frees it and runs it through jwt_key2jwk).
	 * Returns 0 on success, non-zero on an unsupported type/param/curve or a
	 * runtime-incapable backend. NULL if the backend cannot generate keys.
	 * "oct" is generated in common code (jwt_ops->rng), not here. */
	int (*generate_pem)(jwk_key_type_t kty, const char *param, jwt_alg_t alg,
			    char **pem_out, size_t *pem_len);

	/* One-shot SHA-2 digest. @sha_bits selects the hash (256/384/512).
	 * Writes the raw digest into @out (the caller provides a buffer of at
	 * least 64 bytes) and sets *@out_len. Returns 0 on success. Backed by
	 * each backend's native digest. Used by the @rfc{7638} JWK thumbprint;
	 * every backend provides it (it is not gated by jwe_implemented). */
	int (*sha)(int sha_bits, const unsigned char *in, size_t in_len,
		   unsigned char *out, unsigned int *out_len);

	/* @rfc{8018} PBKDF2-HMAC-SHA{256,384,512}: derive @dk_len octets into
	 * @out from the password @pw and @salt over @iter iterations. Used by the
	 * PBES2 (RFC 7518 4.8) JWE key-management algorithms. Returns 0 on
	 * success. NULL on a backend that cannot derive (PBES2 then fails cleanly). */
	int (*pbkdf2)(int sha_bits, const unsigned char *pw, size_t pw_len,
		      const unsigned char *salt, size_t salt_len,
		      unsigned int iter, unsigned char *out, size_t dk_len);

	/* JWE (RFC 7516/7518). A backend may implement JWE crypto ops even if
	 * it does not parse JWKs (JWK parsing always falls back to OpenSSL).
	 * jwe_implemented is set once a backend provides the ops below; until
	 * then, JWE operations on that backend fail cleanly. The ops are
	 * declared here for all stages; each is filled in by its own stage and
	 * left NULL otherwise. */
	int jwe_implemented;

	/* CSPRNG: fill out[0..len) with cryptographically random bytes.
	 * Returns 0 on success. Backed by each backend's native RNG. */
	int (*rng)(unsigned char *out, size_t len);

	/* Content encryption (the "enc" algorithms). AAD is the ASCII bytes of
	 * the encoded protected header. */
	int (*encrypt_aes_gcm)(jwe_enc_t enc, const unsigned char *cek,
		size_t cek_len, const unsigned char *iv, size_t iv_len,
		const unsigned char *aad, size_t aad_len,
		const unsigned char *pt, size_t pt_len,
		unsigned char **ct, size_t *ct_len,
		unsigned char **tag, size_t *tag_len);
	int (*decrypt_aes_gcm)(jwe_enc_t enc, const unsigned char *cek,
		size_t cek_len, const unsigned char *iv, size_t iv_len,
		const unsigned char *aad, size_t aad_len,
		const unsigned char *ct, size_t ct_len,
		const unsigned char *tag, size_t tag_len,
		unsigned char **pt, size_t *pt_len);
	int (*encrypt_aes_cbc_hmac)(jwe_enc_t enc, const unsigned char *cek,
		size_t cek_len, const unsigned char *iv, size_t iv_len,
		const unsigned char *aad, size_t aad_len,
		const unsigned char *pt, size_t pt_len,
		unsigned char **ct, size_t *ct_len,
		unsigned char **tag, size_t *tag_len);
	int (*decrypt_aes_cbc_hmac)(jwe_enc_t enc, const unsigned char *cek,
		size_t cek_len, const unsigned char *iv, size_t iv_len,
		const unsigned char *aad, size_t aad_len,
		const unsigned char *ct, size_t ct_len,
		const unsigned char *tag, size_t tag_len,
		unsigned char **pt, size_t *pt_len);

	/* Key management: AES Key Wrap (RFC 3394). Key-mgmt shaped: a CEK goes
	 * in, the wrapped key comes out (and the inverse). */
	int (*wrap_aes_kw)(const jwk_item_t *key, const unsigned char *cek,
		size_t cek_len, unsigned char **out, size_t *out_len);
	int (*unwrap_aes_kw)(const jwk_item_t *key, const unsigned char *in,
		size_t in_len, unsigned char **cek, size_t *cek_len);

	/* AES Key Wrap with a raw KEK (the agreed key in ECDH-ES+A*KW). */
	int (*wrap_aes_kw_raw)(const unsigned char *kek, size_t kek_len,
		const unsigned char *cek, size_t cek_len,
		unsigned char **out, size_t *out_len);
	int (*unwrap_aes_kw_raw)(const unsigned char *kek, size_t kek_len,
		const unsigned char *in, size_t in_len,
		unsigned char **cek, size_t *cek_len);

	/* Key management: RSAES-OAEP (and OAEP-256). */
	int (*encrypt_cek_rsa)(jwe_key_alg_t alg, const jwk_item_t *key,
		const unsigned char *cek, size_t cek_len,
		unsigned char **out, size_t *out_len);
	int (*decrypt_cek_rsa)(jwe_key_alg_t alg, const jwk_item_t *key,
		const unsigned char *in, size_t in_len,
		unsigned char **cek, size_t *cek_len);

	/* ECDH-ES (RFC 7518 4.6). On encrypt, generates an ephemeral keypair,
	 * writes the "epk" into the header, and derives the agreed key via the
	 * Concat KDF. On decrypt, reads "epk" from the header and derives the
	 * same key. The derived key is the CEK (ECDH-ES) or a KEK (ECDH-ES+KW). */
	int (*ecdh_derive)(jwe_key_alg_t alg, jwe_enc_t enc,
		const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
		unsigned char **dk, size_t *dk_len);
};

#ifdef HAVE_OPENSSL
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_openssl_ops;
#endif
#ifdef HAVE_GNUTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_gnutls_ops;
#endif
#ifdef HAVE_MBEDTLS
JWT_NO_EXPORT
extern struct jwt_crypto_ops jwt_mbedtls_ops;
#endif

/* Memory allocators. */
JWT_NO_EXPORT
void *jwt_malloc(size_t size);
JWT_NO_EXPORT
void __jwt_freemem(void *ptr);

JWT_NO_EXPORT
jwt_t *jwt_new(void);

#define jwt_freemem(__ptr) ({		\
	if (__ptr) {			\
		__jwt_freemem(__ptr);	\
		__ptr = NULL;		\
	}				\
})

/* Portable secure zeroization. Writes through a volatile pointer so the
 * compiler may not optimize the wipe away (the property OPENSSL_cleanse and
 * explicit_bzero provide). Backend-agnostic: no OpenSSL dependency, so this
 * works when libjwt is built without the OpenSSL backend. */
static inline void jwt_cleanse(void *__ptr, size_t __len)
{
	if (__ptr == NULL || __len == 0)
		return;

	volatile unsigned char *__p = (volatile unsigned char *)__ptr;
	while (__len--)
		*__p++ = 0;
}

/* Scrub and free sensitive key material. */
#define jwt_scrub_and_free(__ptr, __len) ({	\
	jwt_cleanse(__ptr, __len);		\
	jwt_freemem(__ptr);			\
})

/* Append a raw key component to a jwk_export_t, taking ownership of @data
 * (the common jwt_key2jwk() scrubs and frees it). */
static inline void jwk_export_add(jwk_export_t *out, const char *name,
				  unsigned char *data, size_t len)
{
	if (out->nparams >= JWK_EXPORT_MAX_PARAMS) {
		// LCOV_EXCL_START
		jwt_scrub_and_free(data, len);
		return;
		// LCOV_EXCL_STOP
	}

	out->params[out->nparams].name = name;
	out->params[out->nparams].data = data;
	out->params[out->nparams].len = len;
	out->nparams++;
}

/* Convert a native key (PEM, DER, or — with JWK_KEY_TRY_HMAC — raw HMAC bytes)
 * into one or more JWK JSON objects appended to @out_array. Backend-neutral:
 * asymmetric parsing is dispatched to jwt_ops->key2jwk_params and the JWK is
 * assembled here. Returns 0 if a key (or HMAC fallback) was produced, else -1. */
JWT_NO_EXPORT
int jwt_key2jwk(const char *key, size_t len, unsigned int flags,
		jwt_json_t *out_array);

/* @rfc{7638} Stamp the thumbprint "kid" on @jwk when JWK_KEY_GEN_KID is in
 * @flags (used by jwt_key2jwk and the oct path of jwks_generate). */
JWT_NO_EXPORT
void jwt_gen_kid(jwt_json_t *jwk, jwk_key_type_t kty, unsigned int flags);

/* Core @rfc{7638} JWK thumbprint: base64url(SHA-@bits) over the canonical JWK
 * assembled from @jwk's required members for key type @kty. @bits is 256/384/512.
 * Returns a malloc'd string (caller frees) or NULL. Shared by the public
 * jwks_item_thumbprint() and the key2jwk "kid" generator. */
JWT_NO_EXPORT
char *jwt_jwk_thumbprint(const jwt_json_t *jwk, jwk_key_type_t kty, int bits);

static inline void jwt_freememp(char **mem) {
	jwt_freemem(*mem);
}
#define char_auto char  __attribute__((cleanup(jwt_freememp)))

JWT_NO_EXPORT
void jwt_free(jwt_t *jwt);

static inline void jwt_freep(jwt_t **jwt) {
	if (jwt) {
		jwt_free(*jwt);
		*jwt = NULL;
	}
}
#define jwt_auto_t jwt_t __attribute__((cleanup(jwt_freep)))

/* Helper routines to handle base64url encoding without percent padding
 * as defined in RFC-4648. */
JWT_NO_EXPORT
int jwt_base64uri_encode(char **_dst, const char *plain, int plain_len);
JWT_NO_EXPORT
void *jwt_base64uri_decode(const char *src, int *ret_len);

JWT_NO_EXPORT
jwt_t *jwt_verify_sig(jwt_t *jwt, const char *head, unsigned int head_len,
                   const char *sig);
JWT_NO_EXPORT
int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str,
	     unsigned int str_len);

JWT_NO_EXPORT
jwt_value_error_t __deleter(jwt_json_t *which, const char *field);
JWT_NO_EXPORT
jwt_value_error_t __setter(jwt_json_t *which, jwt_value_t *value);
JWT_NO_EXPORT
jwt_value_error_t __getter(jwt_json_t *which, jwt_value_t *value);

JWT_NO_EXPORT
int jwt_parse(jwt_t *jwt, const char *token, unsigned int *len);
JWT_NO_EXPORT
int jwt_check_crit(jwt_t *jwt, char * const *understood);
JWT_NO_EXPORT
int jwt_write_crit(jwt_t *jwt, char * const *crit);
JWT_NO_EXPORT
jwt_t *jwt_verify_complete(jwt_t *jwt, const jwt_config_t *config,
			   const char *token, unsigned int payload_len);

JWT_NO_EXPORT
char *jwt_encode_str(jwt_t *jwt);

JWT_NO_EXPORT
int jwt_head_setup(jwt_t *jwt);

/* @rfc{7515,7.2} JWS JSON Serialization (multi-signature) helpers.
 *
 * The jwt_signature list helpers mirror the jwe_recipient ones: a Compact/
 * Flattened JWS is a one-element list, General is N. Owned by jwt_common. */
JWT_NO_EXPORT
struct jwt_signature *jwt_signature_first(struct jwt_common *cmd);
JWT_NO_EXPORT
struct jwt_signature *jwt_signature_append(struct jwt_common *cmd);
JWT_NO_EXPORT
struct jwt_signature *jwt_signature_first_or_add(struct jwt_common *cmd);
JWT_NO_EXPORT
void jwt_signature_free(struct jwt_signature *s);

/* Builder: serialize @cmd's signatures + finalized claims (@jwt->claims) into a
 * JWS JSON Serialization (Flattened or General). Returns a malloc'd string. */
JWT_NO_EXPORT
char *jwt_encode_json(jwt_t *jwt, struct jwt_common *cmd);

/* @rfc{7797} The payload as it appears after the first '.': raw bytes or
 * serialized claims, base64url-encoded unless jwt->b64 is false. Malloc'd,
 * NUL-terminated, binary-safe via @out_len. 0 on success. */
JWT_NO_EXPORT
int jwt_build_payload_part(jwt_t *jwt, char **out, size_t *out_len);

/* @rfc{7797,6} Inject "b64":false + "b64" in "crit" into jwt->headers (for an
 * unencoded payload). 0 on success. */
JWT_NO_EXPORT
int jwt_apply_b64_header(jwt_t *jwt);

/* Checker: parse + verify a JWS JSON Serialization against the checker's
 * key/keyring and policy. Returns 0 if the policy is satisfied. */
JWT_NO_EXPORT
int jwt_verify_json(jwt_checker_t *checker, const char *token);

/* @rfc{7515,7.2.1} Non-zero if any member of @header also appears in
 * @protected (a parameter must not be in both). */
JWT_NO_EXPORT
int jwt_header_params_overlap(const jwt_json_t *protected,
			      const jwt_json_t *header);

/* JWE alg/enc <-> string maps (jwe-setget.c). These are exported as part of
 * the public API (jwe_alg_str etc.), declared in jwt.h. */

#define __trace() fprintf(stderr, "%s:%d\n", __func__, __LINE__)

/* Returns the jwk_key_type_t that the given JWA algorithm requires, or
 * JWK_KEY_TYPE_NONE for JWT_ALG_NONE / unknown values. This is the
 * authoritative kty<->alg mapping used to prevent algorithm confusion
 * attacks (e.g. GHSA-q843-6q5f-w55g): an RSA JWK must never be usable
 * for an HS* token, regardless of whether the JWK carries an alg hint. */
static inline jwk_key_type_t jwt_alg_required_kty(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return JWK_KEY_TYPE_OCT;

	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:
	case JWT_ALG_PS256:
	case JWT_ALG_PS384:
	case JWT_ALG_PS512:
		return JWK_KEY_TYPE_RSA;

	case JWT_ALG_ES256:
	case JWT_ALG_ES256K:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		return JWK_KEY_TYPE_EC;

	case JWT_ALG_EDDSA:
		return JWK_KEY_TYPE_OKP;

#ifdef LIBJWT_HAVE_ML_DSA
	case JWT_ALG_ML_DSA_44:
	case JWT_ALG_ML_DSA_65:
	case JWT_ALG_ML_DSA_87:
		return JWK_KEY_TYPE_AKP;
#endif

	// LCOV_EXCL_START
	default:
		return JWK_KEY_TYPE_NONE;
	// LCOV_EXCL_STOP
	}
}

/* @rfc{7518,5.1} The CEK length (in bytes) required by a content encryption
 * ("enc") algorithm. The AES-CBC-HMAC algorithms use a double-length key
 * (MAC_KEY || ENC_KEY), hence 32/48/64 bytes. Returns 0 for invalid enc. */
static inline size_t jwe_enc_cek_len(jwe_enc_t enc)
{
	switch (enc) {
	case JWE_ENC_A128GCM:
		return 16;
	case JWE_ENC_A192GCM:
		return 24;
	case JWE_ENC_A256GCM:
		return 32;
	case JWE_ENC_A128CBC_HS256:
		return 32;
	case JWE_ENC_A192CBC_HS384:
		return 48;
	case JWE_ENC_A256CBC_HS512:
		return 64;
	default:
		return 0;
	}
}

/* @rfc{7518,4.1} The IV length (in bytes) for a content encryption algorithm:
 * 96-bit nonce for GCM, 128-bit IV for CBC. Returns 0 for invalid enc. */
static inline size_t jwe_enc_iv_len(jwe_enc_t enc)
{
	switch (enc) {
	case JWE_ENC_A128GCM:
	case JWE_ENC_A192GCM:
	case JWE_ENC_A256GCM:
		return 12;
	case JWE_ENC_A128CBC_HS256:
	case JWE_ENC_A192CBC_HS384:
	case JWE_ENC_A256CBC_HS512:
		return 16;
	default:
		return 0;
	}
}

/* The jwk_key_type_t that a JWE key management ("alg") algorithm requires of
 * the recipient key. Mirrors jwt_alg_required_kty() for JWE and is the
 * authoritative kty<->alg gate that prevents using, e.g., an RSA key for an
 * AES Key Wrap operation. JWE_KEY_TYPE_NONE for invalid/unknown. */
static inline jwk_key_type_t jwe_alg_required_kty(jwe_key_alg_t alg)
{
	switch (alg) {
	case JWE_ALG_DIR:
	case JWE_ALG_A128KW:
	case JWE_ALG_A192KW:
	case JWE_ALG_A256KW:
	case JWE_ALG_A128GCMKW:
	case JWE_ALG_A192GCMKW:
	case JWE_ALG_A256GCMKW:
	case JWE_ALG_PBES2_HS256_A128KW:
	case JWE_ALG_PBES2_HS384_A192KW:
	case JWE_ALG_PBES2_HS512_A256KW:
		return JWK_KEY_TYPE_OCT;

	case JWE_ALG_RSA_OAEP:
	case JWE_ALG_RSA_OAEP_256:
		return JWK_KEY_TYPE_RSA;

	case JWE_ALG_ECDH_ES:
	case JWE_ALG_ECDH_ES_A128KW:
	case JWE_ALG_ECDH_ES_A192KW:
	case JWE_ALG_ECDH_ES_A256KW:
		/* ECDH-ES uses an EC (or, in a later release, OKP X25519/X448)
		 * key. EC is the required type for the supported curves. */
		return JWK_KEY_TYPE_EC;

	// LCOV_EXCL_START
	default:
		return JWK_KEY_TYPE_NONE;
	// LCOV_EXCL_STOP
	}
}

/* JWE shared helpers (jwe.c). Generate a fresh CEK for the given enc via the
 * active backend's rng. Returns 0 on success and allocates *cek (the caller
 * scrubs and frees it). */
/* Generate a fresh CEK for the given enc via the active backend's rng.
 * Returns 0 on success and allocates *cek (caller scrubs+frees). */
JWT_NO_EXPORT
int jwe_generate_cek(jwe_enc_t enc, unsigned char **cek, size_t *cek_len);

/* AES Key Wrap (RFC 3394) of / unwrap to the CEK for an A*KW alg. The KEK is
 * the recipient oct key; its length must match the alg. Return 0 on success.
 * Unwrap failure (wrong KEK or tampered key) returns non-zero. */
JWT_NO_EXPORT
int jwe_wrap_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		 const unsigned char *cek, size_t cek_len,
		 unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int jwe_unwrap_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		   const unsigned char *in, size_t in_len,
		   unsigned char **cek, size_t *cek_len);

/* Encrypt/recover the CEK for any non-dir key management alg (A*KW or
 * RSA-OAEP). jwe_decrypt_cek failure is handled by the caller via the
 * RFC 7516 11.5 random-CEK substitution. */
JWT_NO_EXPORT
int jwe_encrypt_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		    const unsigned char *cek, size_t cek_len,
		    unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int jwe_decrypt_cek(jwe_key_alg_t alg, const jwk_item_t *key,
		    const unsigned char *in, size_t in_len,
		    unsigned char **cek, size_t *cek_len);

/* AES-GCM Key Wrap (RFC 7518 4.7). Wrap/unwrap the CEK by GCM-encrypting it
 * under the oct KEK with a fresh 96-bit IV (mandatory) and empty AAD; the IV
 * and tag are carried in the per-recipient header (@hdr) as "iv"/"tag". */
JWT_NO_EXPORT
int jwe_alg_is_gcmkw(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_gcmkw_wrap(jwe_key_alg_t alg, const jwk_item_t *key,
		   const unsigned char *cek, size_t cek_len,
		   jwt_json_t *hdr, unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int jwe_gcmkw_unwrap(jwe_key_alg_t alg, const jwk_item_t *key, jwt_json_t *hdr,
		     const unsigned char *in, size_t in_len,
		     unsigned char **cek, size_t *cek_len);

/* PBES2 password-based key management (RFC 7518 4.8). PBKDF2 (over a fresh salt)
 * derives a KEK from the oct key's octets (the password); the CEK is AES-KW
 * wrapped. "p2s" (salt) and "p2c" (iterations) ride in the per-recipient header;
 * @p2c on wrap is 0 for the default. The decrypt side caps p2c and the salt. */
JWT_NO_EXPORT
int jwe_alg_is_pbes2(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_pbes2_wrap(jwe_key_alg_t alg, const jwk_item_t *key,
		   const unsigned char *cek, size_t cek_len, unsigned int p2c,
		   jwt_json_t *hdr, unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int jwe_pbes2_unwrap(jwe_key_alg_t alg, const jwk_item_t *key, jwt_json_t *hdr,
		     const unsigned char *in, size_t in_len,
		     unsigned char **cek, size_t *cek_len);

/* ECDH-ES (RFC 7518 4.6). Direct mode derives the CEK directly. */
JWT_NO_EXPORT
int jwe_alg_is_ecdh(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_alg_is_ecdh_direct(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_alg_is_direct(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc, const jwk_item_t *key,
		    int for_encrypt, jwt_json_t *hdr,
		    unsigned char **dk, size_t *dk_len);

/* AES Key Wrap / Unwrap with a raw KEK (ECDH-ES+A*KW agreed key). */
JWT_NO_EXPORT
int jwe_aeskw_wrap_raw(const unsigned char *kek, size_t kek_len,
		       const unsigned char *cek, size_t cek_len,
		       unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int jwe_aeskw_unwrap_raw(const unsigned char *kek, size_t kek_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char **cek, size_t *cek_len);

/* Dispatch JWE content encryption/decryption to the active backend for the
 * given enc. Return 0 on success. Decrypt verifies the AEAD tag. */
JWT_NO_EXPORT
int jwe_encrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
JWT_NO_EXPORT
int jwe_decrypt_content(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);

/* Validate that a JWK may be used for a JWE operation with the given key
 * management alg. Checks key type vs alg, the "use" attribute (must not be
 * "sig"), and "key_ops" (if present, must permit the needed operation).
 * @for_encrypt selects the producer (encrypt/wrap) vs consumer (decrypt/
 * unwrap) direction. Returns NULL if the key is acceptable, or a static
 * human-readable reason string if not. */
JWT_NO_EXPORT
const char *jwe_key_usage_check(const jwk_item_t *key, jwe_key_alg_t alg,
				int for_encrypt);

/* @rfc{7516,5.1} step 14 Build the Additional Authenticated Data for the AEAD.
 * Compact and the JSON serializations agree on the base: ASCII(@protected_b64).
 * When a JWE "aad" member is present (its base64url form passed as @aad_b64),
 * the AAD becomes ASCII(@protected_b64 || '.' || @aad_b64). On return *@aad
 * points at the AAD bytes and *@aad_len is its length. If *@owned is set, the
 * caller must free *@aad; otherwise *@aad aliases @protected_b64 (the no-aad
 * case, byte-identical to the Compact Serialization) and must not be freed.
 * Returns 0 on success, non-zero on allocation failure. */
JWT_NO_EXPORT
int jwe_build_aad(const char *protected_b64, const char *aad_b64,
		  const unsigned char **aad, size_t *aad_len, int *owned);

/* Recipient list helpers (jwe.c). A recipient is heap-allocated and linked
 * into jwe_common.recipients. jwe_recipient_first() returns the first recipient
 * or NULL; jwe_recipient_first_or_add() returns it, creating an empty one if
 * the list is empty (used by the legacy single-key setkey path).
 * jwe_recipient_append() always adds a new recipient. jwe_recipient_free()
 * frees one recipient and its owned members. */
JWT_NO_EXPORT
struct jwe_recipient *jwe_recipient_first(struct jwe_common *cmd);
JWT_NO_EXPORT
struct jwe_recipient *jwe_recipient_first_or_add(struct jwe_common *cmd);
JWT_NO_EXPORT
struct jwe_recipient *jwe_recipient_append(struct jwe_common *cmd);
JWT_NO_EXPORT
void jwe_recipient_free(struct jwe_recipient *r);

#endif /* JWT_PRIVATE_H */
