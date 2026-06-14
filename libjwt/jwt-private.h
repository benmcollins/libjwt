/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
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
#include <openssl/crypto.h>

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

/******************************/

/* JWE is kept deliberately separate from JWS/JWT. A JWE is structurally and
 * cryptographically different (5 parts, "alg"+"enc", a CEK), so it gets its
 * own common struct rather than overloading struct jwt_common. */
struct jwe_common {
	jwe_key_alg_t key_alg;	/* @rfc{7516,4.1.1} "alg" key management	*/
	jwe_enc_t enc;		/* @rfc{7516,4.1.2} "enc" content encryption	*/
	const jwk_item_t *key;	/* Recipient key used for key management		*/
	jwt_json_t *payload;	/* Claims/plaintext to encrypt (builder)	*/
	jwt_json_t *headers;	/* Protected header				*/
	jwt_callback_t cb;
	void *cb_ctx;

	/* The five JWE Compact Serialization components, populated during
	 * encrypt (builder) or decrypt (checker). Owned by this struct. */
	unsigned char *cek;	/* Content Encryption Key			*/
	size_t cek_len;
	unsigned char *enckey;	/* JWE Encrypted Key (wrapped CEK)		*/
	size_t enckey_len;
	unsigned char *iv;	/* JWE Initialization Vector			*/
	size_t iv_len;
	unsigned char *ct;	/* JWE Ciphertext				*/
	size_t ct_len;
	unsigned char *tag;	/* JWE Authentication Tag			*/
	size_t tag_len;
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
	void (*process_item_free)(jwk_item_t *item);

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

/* Scrub and free sensitive key material. Uses OPENSSL_cleanse which is
 * available on all platforms (OpenSSL >= 3.0 is always required). */
#define jwt_scrub_and_free(__ptr, __len) ({	\
	if (__ptr)				\
		OPENSSL_cleanse(__ptr, __len);	\
	jwt_freemem(__ptr);			\
})

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

/* ECDH-ES (RFC 7518 4.6). Direct mode derives the CEK directly. */
JWT_NO_EXPORT
int jwe_alg_is_ecdh(jwe_key_alg_t alg);
JWT_NO_EXPORT
int jwe_alg_is_ecdh_direct(jwe_key_alg_t alg);
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

#endif /* JWT_PRIVATE_H */
