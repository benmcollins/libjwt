/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file jwt.h
 * @brief The C JSON Web Token Library +JWK + JWKS
 *
 * @include{doc} mainpage.dox
 * @include{doc} examples.dox
 */

#ifndef JWT_H
#define JWT_H

#include <jwt_export.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup jwt_claims_helpers_grp
 * @brief Integer type used for numeric claim and header values
 *
 * Defined as ``long long`` when supported, otherwise ``long``; this is the
 * type of the integer member of @ref jwt_value_t.
 *
 * @since 3.2.2
 */
#if JWT_USES_LONG_LONG
typedef long long jwt_long_t;
#else
typedef long jwt_long_t;
#endif /* JWT_USES_LONG_LONG */

/** @ingroup jwt_object_grp
 * @brief Opaque JWT object
 *
 * Used in callbacks when generating or verifying a JWT
 * @since 3.0.0
 */
typedef struct jwt jwt_t;

/** @ingroup jwks_core_grp
 * @brief Opaque JWKS object
 *
 * Used for working with JSON Web Keys and JWK Sets (JWKS).
 *
 * @remark All JWK operations require that you import your JWK into a jwk_set_t
 * first. Internal, LibJWT creates a jwk_set_t even for single keys. This makes
 * code pretty much the same whether working with one JWK or a set of them.
 * @since 3.0.0
 */
typedef struct jwk_set jwk_set_t;

/** @ingroup jwt_alg_grp
 * @brief JWT algorithm types
 *
 * These are the supported algorithm types for LibJWT.
 *
 * @rfc{7518,3.1}
 * @since 3.0.0
 */
typedef enum {
	JWT_ALG_NONE = 0,	/**< No signature */
	JWT_ALG_HS256,		/**< HMAC using SHA-256 */
	JWT_ALG_HS384,		/**< HMAC using SHA-384 */
	JWT_ALG_HS512,		/**< HMAC using SHA-512 */
	JWT_ALG_RS256,		/**< RSASSA-PKCS1-v1_5 using SHA-256 */
	JWT_ALG_RS384,		/**< RSASSA-PKCS1-v1_5 using SHA-384 */
	JWT_ALG_RS512,		/**< RSASSA-PKCS1-v1_5 using SHA-512 */
	JWT_ALG_ES256,		/**< ECDSA using P-256 and SHA-256 */
	JWT_ALG_ES384,		/**< ECDSA using P-384 and SHA-384 */
	JWT_ALG_ES512,		/**< ECDSA using P-521 and SHA-512 */
	JWT_ALG_PS256,		/**< RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
	JWT_ALG_PS384,		/**< RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
	JWT_ALG_PS512,		/**< RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
	JWT_ALG_ES256K,		/**< ECDSA using secp256k1 and SHA-256 */
	JWT_ALG_EDDSA,		/**< EdDSA using Ed25519 or Ed448 */
	JWT_ALG_ML_DSA_44,	/**< ML-DSA-44 (FIPS 204, RFC 9964) (experimental) @since 3.5.0 */
	JWT_ALG_ML_DSA_65,	/**< ML-DSA-65 (FIPS 204, RFC 9964) (experimental) @since 3.5.0 */
	JWT_ALG_ML_DSA_87,	/**< ML-DSA-87 (FIPS 204, RFC 9964) (experimental) @since 3.5.0 */
	JWT_ALG_INVAL,		/**< An invalid algorithm from the caller or the token */
} jwt_alg_t;

/** @ingroup jwt_alg_grp
 * @brief JWE key management algorithm types
 *
 * These are the supported JWE ``"alg"`` (key management) algorithm types for
 * LibJWT. They determine how the Content Encryption Key (CEK) is produced for
 * or recovered from a recipient. They are intentionally a separate type from
 * @ref jwt_alg_t (which is JWS/signing only); the ``"alg"`` values used in JWE
 * and JWS are not the same.
 *
 * @rfc{7518,4.1}
 * @since 3.4.0
 */
typedef enum {
	JWE_ALG_NONE = 0,	/**< No/unset key management algorithm */
	JWE_ALG_DIR,		/**< Direct use of a shared symmetric key as the CEK */
	JWE_ALG_A128KW,		/**< AES Key Wrap with 128-bit key */
	JWE_ALG_A192KW,		/**< AES Key Wrap with 192-bit key */
	JWE_ALG_A256KW,		/**< AES Key Wrap with 256-bit key */
	JWE_ALG_RSA_OAEP,	/**< RSAES-OAEP using default (SHA-1) parameters */
	JWE_ALG_RSA_OAEP_256,	/**< RSAES-OAEP using SHA-256 and MGF1 with SHA-256 */
	JWE_ALG_ECDH_ES,	/**< ECDH-ES using Concat KDF (Direct Key Agreement) */
	JWE_ALG_ECDH_ES_A128KW,	/**< ECDH-ES using Concat KDF and CEK wrapped with A128KW */
	JWE_ALG_ECDH_ES_A192KW,	/**< ECDH-ES using Concat KDF and CEK wrapped with A192KW */
	JWE_ALG_ECDH_ES_A256KW,	/**< ECDH-ES using Concat KDF and CEK wrapped with A256KW */
	JWE_ALG_A128GCMKW,	/**< Key wrapping with AES GCM using a 128-bit key @since 3.6.0 */
	JWE_ALG_A192GCMKW,	/**< Key wrapping with AES GCM using a 192-bit key @since 3.6.0 */
	JWE_ALG_A256GCMKW,	/**< Key wrapping with AES GCM using a 256-bit key @since 3.6.0 */
	JWE_ALG_PBES2_HS256_A128KW,	/**< PBES2 with HMAC SHA-256 and A128KW wrapping @since 3.6.0 */
	JWE_ALG_PBES2_HS384_A192KW,	/**< PBES2 with HMAC SHA-384 and A192KW wrapping @since 3.6.0 */
	JWE_ALG_PBES2_HS512_A256KW,	/**< PBES2 with HMAC SHA-512 and A256KW wrapping @since 3.6.0 */
	JWE_ALG_INVAL,		/**< An invalid algorithm from the caller or the token */
} jwe_key_alg_t;

/** @ingroup jwt_alg_grp
 * @brief JWE content encryption algorithm types
 *
 * These are the supported JWE ``"enc"`` (content encryption) algorithm types
 * for LibJWT. They determine the authenticated encryption applied to the
 * plaintext using the CEK.
 *
 * @rfc{7518,5.1}
 * @since 3.4.0
 */
typedef enum {
	JWE_ENC_NONE = 0,	/**< No/unset content encryption algorithm */
	JWE_ENC_A128GCM,	/**< AES GCM using 128-bit key */
	JWE_ENC_A192GCM,	/**< AES GCM using 192-bit key */
	JWE_ENC_A256GCM,	/**< AES GCM using 256-bit key */
	JWE_ENC_A128CBC_HS256,	/**< AES 128 CBC + HMAC SHA-256 (truncated) */
	JWE_ENC_A192CBC_HS384,	/**< AES 192 CBC + HMAC SHA-384 (truncated) */
	JWE_ENC_A256CBC_HS512,	/**< AES 256 CBC + HMAC SHA-512 (truncated) */
	JWE_ENC_INVAL,		/**< An invalid algorithm from the caller or the token */
} jwe_enc_t;

/** @ingroup jwt_alg_grp
 * @brief JWE serialization formats
 *
 * RFC 7516 defines two serializations. The Compact Serialization is the
 * five-part ``header.encrypted_key.iv.ciphertext.tag`` string and supports a
 * single recipient. The JSON Serialization is a JSON object; its Flattened
 * form is the single-recipient special case, and its General form carries a
 * ``recipients`` array for one or more recipients.
 *
 * @rfc{7516,7}
 * @since 3.4.0
 */
typedef enum {
	JWE_FORMAT_COMPACT = 0,	/**< @rfc{7516,7.1} Compact Serialization (default) */
	JWE_FORMAT_JSON_FLAT,	/**< @rfc{7516,7.2.2} Flattened JSON Serialization */
	JWE_FORMAT_JSON_GENERAL,/**< @rfc{7516,7.2.1} General JSON Serialization */
} jwe_serialization_t;

/** @ingroup jwt_crypto_grp
 * @brief  Different providers for crypto operations
 *
 * Used to set or test the underlying cryptographic library provider.
 *
 * @remark These being present are not a guarantee that the JWT library
 *  has been compiled to support it. Also, certain functions of the
 *  library may not be supported by each. For example, not all of them
 *  support JWKS operations.
 * @since 3.0.0
 **/
typedef enum {
	JWT_CRYPTO_OPS_NONE = 0,	/**< Used for error handling */
	JWT_CRYPTO_OPS_OPENSSL,		/**< OpenSSL Library */
	JWT_CRYPTO_OPS_GNUTLS,		/**< GnuTLS Library */
	JWT_CRYPTO_OPS_MBEDTLS,		/**< MBedTLS embedded library */
	JWT_CRYPTO_OPS_ANY,		/**< Used internally for hmac keys */
} jwt_crypto_provider_t;

/** @ingroup jwks_item_grp
 * @brief JWK Key Types
 *
 * Corresponds to the ``"kty"`` attribute of the JWK.
 *
 * @rfc{7517,4.1}
 * @rfc{7518,6.1}
 * @since 3.0.0
 */
typedef enum {
	JWK_KEY_TYPE_NONE = 0,		/**< Unused on valid keys */
	JWK_KEY_TYPE_EC,		/**< Elliptic Curve keys */
	JWK_KEY_TYPE_RSA,		/**< RSA keys (RSA and RSA-PSS) */
	JWK_KEY_TYPE_OKP,		/**< Octet Key Pair (e.g. EdDSA) */
	JWK_KEY_TYPE_OCT,		/**< Octet sequence (e.g. HS256) */
	JWK_KEY_TYPE_AKP,		/**< Algorithm Key Pair (e.g. ML-DSA) @rfc{9964,3} @since 3.5.0 */
} jwk_key_type_t;

/** @ingroup jwks_item_grp
 * @brief Usage types for JWK public keys
 *
 * Corresponds to the ``"use"`` attribute in a JWK the represents a public key.
 *
 * @rfc{7517,4.2}
 * @since 3.0.0
 **/
typedef enum {
	JWK_PUB_KEY_USE_NONE = 0,	/**< No usable attribute was set */
	JWK_PUB_KEY_USE_SIG,		/**< Signature key (JWS) */
	JWK_PUB_KEY_USE_ENC,		/**< Encryption key (JWE) */
} jwk_pub_key_use_t;

/** @ingroup jwks_item_grp
 * @brief Allowed key operations for JWK private keys
 *
 * Corresponds to the ``"key_ops"`` attribute in a JWK that represents a private
 * key. These can be bitwise compares to the key_ops attribute of a jwk_item_t.
 * These flags are used internally to decide if a JWK can be used
 * for certain operations.
 *
 * @code
 * if (jwk_item_t.key_ops & (JWK_KEY_OP_SIGN | JWK_KEY_OP_ENCRYPT)) {
 *     ...
 * }
 * @endcode
 *
 * @rfc{7517,4.3}
 * @since 3.0.0
 **/
typedef enum {
	JWK_KEY_OP_NONE		= 0x0000,	/**< No key_op set */
	JWK_KEY_OP_SIGN		= 0x0001,	/**< Signing */
	JWK_KEY_OP_VERIFY	= 0x0002,	/**< Signature verification */
	JWK_KEY_OP_ENCRYPT	= 0x0004,	/**< Used for encryption */
	JWK_KEY_OP_DECRYPT	= 0x0008,	/**< Used for decrypting */
	JWK_KEY_OP_WRAP		= 0x0010,	/**< For wrapping other keys */
	JWK_KEY_OP_UNWRAP	= 0x0020,	/**< For unwrappng other keys */
	JWK_KEY_OP_DERIVE_KEY	= 0x0040,	/**< Key derivation */
	JWK_KEY_OP_DERIVE_BITS	= 0x0080,	/**< Bits derivation */
	JWK_KEY_OP_INVALID	= 0xffff,	/**< Invalid key_ops in JWK */
} jwk_key_op_t;

/** @ingroup jwt_claims_helpers_grp
 * @brief Value types for claims and headers
 * @since 3.0.0
 */
typedef enum {
	JWT_VALUE_NONE = 0,	/**< No type (do not use this)		*/
	JWT_VALUE_INT,		/**< Integer				*/
	JWT_VALUE_STR,		/**< String				*/
	JWT_VALUE_BOOL,		/**< Boolean				*/
	JWT_VALUE_JSON,		/**< JSON String (``{..}`` or ``[..]``)	*/
	JWT_VALUE_INVALID,	/**< Invalid (used internally)		*/
} jwt_value_type_t;

/** @ingroup jwt_claims_helpers_grp
 * @brief Error values for header and claim requests
 * @since 3.0.0
 */
typedef enum {
	JWT_VALUE_ERR_NONE = 0,	/**< No error, success			*/
	JWT_VALUE_ERR_EXIST,	/**< Item exists (when setting)		*/
	JWT_VALUE_ERR_NOEXIST,	/**< Item doesn't exist (when getting)	*/
	JWT_VALUE_ERR_TYPE,	/**< Item is not of the type requested	*/
	JWT_VALUE_ERR_INVALID,	/**< Invalid request (general error)	*/
	JWT_VALUE_ERR_NOMEM,	/**< Memory allocation error		*/
} jwt_value_error_t;

/** @ingroup jwt_claims_helpers_grp
 * @brief Data type for get and set actions for JWT headers and claims
 *
 * This is used for both set and get requests. Specific rules for each type is
 * described in more detail for the set and get requests.
 *
 * @note There are helper macros to simplify setting this structure properly and
 *  reducing common mistakes. See the jwt_set_{SET,GET}_{INT,STR,BOOL,JSON}
 *  definitions.
 * @since 3.0.0
 */
typedef struct {
	jwt_value_type_t type;
	const char *name;
	union {
		jwt_long_t int_val;
		const char *str_val;
		int bool_val;
		char *json_val;
	};
	int replace;
	int pretty;
	jwt_value_error_t error;
} jwt_value_t;

/** @ingroup jwks_item_grp
 * @brief Object representation of a JWK
 *
 * This object is produced by importing a JWK or JWKS into a  @ref jwk_set_t
 * object. It represents single key and is used when generating or verifying
 * JWT.
 * @since 3.0.0
 */
typedef struct jwk_item jwk_item_t;

/** @ingroup jwt_memory_grp
 * @brief Prototype for malloc(3)
 * @since 3.0.0
 */
typedef void *(*jwt_malloc_t)(size_t);

/** @ingroup jwt_memory_grp
 * @brief Prototype for free(3)
 * @since 3.0.0
 */
typedef void (*jwt_free_t)(void *);

/** @ingroup jwt_alg_grp
 * Get the jwt_alg_t set for this JWT object.
 *
 * Returns the jwt_alg_t type for this JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @returns Returns a jwt_alg_t type for this object.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_alg_t jwt_get_alg(const jwt_t *jwt);

/** @ingroup jwt_object_grp
 * @brief Structure used to pass state with a user callback
 * @since 3.0.0
 */
typedef struct {
	const jwk_item_t *key;	/**< A JWK to use for key	*/
	jwt_alg_t alg;		/**< For algorithm matching	*/
	void *ctx;		/**< User controlled context	*/
} jwt_config_t;

/** @ingroup jwt_object_grp
 * @brief General callback for generation and verification of JWT
 * @since 3.0.0
 */
typedef int (*jwt_callback_t)(jwt_t *, jwt_config_t *);

/** @ingroup jwt_object_grp
 * @brief Callback to generate a ``jti`` (JWT ID) when building a token
 *
 * @rfc_t{7519,4.1.7} The returned string is set as the ``"jti"`` claim and
 * then freed by LibJWT, so it must be allocated with whatever allocator
 * LibJWT is currently using: plain malloc() if jwt_set_alloc() was never
 * called, otherwise the allocator passed to jwt_set_alloc(). Returning NULL
 * aborts token generation. The application is responsible for ensuring the
 * id is unique.
 * @since 3.4.0
 */
typedef char *(*jwt_jti_gen_cb_t)(const jwt_t *, jwt_config_t *);

/** @ingroup jwt_object_grp
 * @brief Callback to verify a ``jti`` (JWT ID) when checking a token
 *
 * @rfc_t{7519,4.1.7} Receives the ``"jti"`` claim from the token. Return 0 to
 * accept the token or non-zero to reject it (e.g. an unknown or
 * already-consumed id). This is where an application implements replay
 * protection against its own id pool.
 * @since 3.4.0
 */
typedef int (*jwt_jti_check_cb_t)(const jwt_t *, jwt_config_t *, const char *);

/** @ingroup jwt_claims_helpers_grp
 * @brief WFC defined claims
 * @since 3.0.0
 */
typedef enum {
        JWT_CLAIM_ISS           = 0x0001, /**< @rfc_t{7519,4.1.1} ``"iss"`` */
        JWT_CLAIM_SUB           = 0x0002, /**< @rfc_t{7519,4.1.2} ``"sub"`` */
        JWT_CLAIM_AUD           = 0x0004, /**< @rfc_t{7519,4.1.3} ``"aud"`` */
        JWT_CLAIM_EXP           = 0x0008, /**< @rfc_t{7519,4.1.4} ``"exp"`` */
        JWT_CLAIM_NBF           = 0x0010, /**< @rfc_t{7519,4.1.5} ``"nbf"`` */
        JWT_CLAIM_IAT           = 0x0020, /**< @rfc_t{7519,4.1.6} ``"iat"`` */
        JWT_CLAIM_JTI           = 0x0040, /**< @rfc_t{7519,4.1.7} ``"jti"`` */
} jwt_claims_t;

/**
 * @defgroup jwt_grp JSON Web Token
 *
 * @brief Create and consume JSON Web Tokens (JWS)
 * @{
 */

/**
 * @defgroup jwt_builder_grp Builder
 *
 * @brief Create and sign JWT tokens
 *
 * Creating a JWT token involves several steps. First is creating a
 * jwt_builder_t object, which can be thought of as a JWT factory. Once
 * configured, you can use it to create tokens with pre-defined claims.
 * @{
 */

/**
 * @brief Opaque Builder Object
 * @since 3.0.0
 */
typedef struct jwt_builder jwt_builder_t;

/**
 * @brief Function to create a new builder instance
 *
 * @return Pointer to a builder object on success, NULL on failure
 * @since 3.0.0
 */
JWT_EXPORT
jwt_builder_t *jwt_builder_new(void);

/**
 * @brief Frees a previously created builder object
 *
 * @param builder Pointer to a builder object
 * @since 3.0.0
 */
JWT_EXPORT
void jwt_builder_free(jwt_builder_t *builder);

#if defined(__GNUC__) || defined(__clang__) || defined(_DOXYGEN)
/**
 * @brief Helper function to free a builder and set the pointer to NULL
 *
 * This is mainly to use with the jwt_builder_auto_t type.
 *
 * @param Pointer to a pointer for a jwt_builder_t object
 * @since 3.0.0
 */
static inline void jwt_builder_freep(jwt_builder_t **builder) {
	if (builder) {
		jwt_builder_free(*builder);
		*builder = NULL;
	}
}
/**
 * @brief A jwt_builder_t pointer that is freed automatically at scope exit
 *
 * Declares a jwt_builder_t pointer carrying the GCC/Clang ``cleanup``
 * attribute so jwt_builder_free() is invoked on it automatically when the
 * variable goes out of scope. Initialize it where you declare it.
 *
 * @since 3.0.0
 */
#define jwt_builder_auto_t jwt_builder_t \
	__attribute__((cleanup(jwt_builder_freep)))
#endif

/**
 * @brief Checks error state of builder object
 *
 * @param builder Pointer to a builder object
 * @return 0 if no errors exist, non-zero otherwise
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_builder_error(const jwt_builder_t *builder);

/**
 * @brief Get the error message contained in a builder object
 *
 * @param builder Pointer to a builder object
 * @return Pointer to a string with the error message. Can be an empty string
 *  if there is no error. Never returns NULL.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwt_builder_error_msg(const jwt_builder_t *builder);

/**
 * @brief Clear error state in a builder object
 *
 * @param builder Pointer to a builder object
 * @since 3.0.0
 */
JWT_EXPORT
void jwt_builder_error_clear(jwt_builder_t *builder);

/**
 * @brief Sets a key and algorithm for a builder
 *
 * The values here must make sense. This table shows what will or won't pass as
 * far as algorithm matching between the alg param and the alg in jwk_item_t.
 * Where ``alg-A`` means one specific algorithm (not none) and ``alg-B``
 * represents another (also not none). The ``none`` is used to represent no
 * algorithm being set. ``NULL`` represents that jwk_item_t pointer is NULL.
 *
 *   alg     | jwt_item_t | Result
 * :-------: | :--------: | :-----------------------:
 * ``alg-A`` | ``alg-A``  | \emoji :white_check_mark:
 * ``none``  | ``alg-A``  | \emoji :white_check_mark:
 * ``alg-A`` | ``none``   | \emoji :white_check_mark:
 * ``none``  | ``NULL``   | \emoji :warning:
 * ``alg-A`` | ``alg-B``  | \emoji :x:
 * ``alg-A`` | ``NULL``   | \emoji :x:
 *
 * @warning The warning represents an insecure token. Using insecure tokens is
 * not very useful and strongly discouraged.
 *
 * @param builder Pointer to a builder object
 * @param alg A valid jwt_alg_t type
 * @param key A JWK key object
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_builder_setkey(jwt_builder_t *builder, const jwt_alg_t alg,
		       const jwk_item_t *key);

/**
 * @brief JWS serialization formats
 *
 * Selects what jwt_builder_generate() emits and is auto-detected by
 * jwt_checker_verify() on input. The Compact Serialization (the default and
 * historic behavior) is a single ``header.payload.signature`` string. The
 * two JSON Serializations (@rfc{7515,7.2}) wrap one or more signatures in a
 * JSON object and are the only forms that can carry multiple signatures or a
 * per-signature unprotected header.
 *
 * @since 3.6.0
 */
typedef enum {
	JWT_FORMAT_COMPACT = 0,	/**< @rfc{7515,7.1} Compact (default)		*/
	JWT_FORMAT_JSON_FLAT,	/**< @rfc{7515,7.2.2} Flattened (single sig)	*/
	JWT_FORMAT_JSON_GENERAL,/**< @rfc{7515,7.2.1} General ("signatures":[])	*/
} jwt_serialization_t;

/**
 * @brief An additional signer on a builder
 *
 * An opaque handle returned by jwt_builder_add_signature(), used to attach a
 * per-signature protected or unprotected header. It is owned by the builder
 * and is valid until jwt_builder_free(); the caller must not free it.
 *
 * @since 3.6.0
 */
typedef struct jwt_signature jwt_signature_t;

/**
 * @brief Select the serialization a builder emits
 *
 * The default is ::JWT_FORMAT_COMPACT. Selecting a JSON form makes
 * jwt_builder_generate() emit the JWS JSON Serialization. Adding a second
 * signer with jwt_builder_add_signature() also forces ::JWT_FORMAT_JSON_GENERAL.
 *
 * @param builder Pointer to a builder object
 * @param format A ::jwt_serialization_t value
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_set_format(jwt_builder_t *builder, jwt_serialization_t format);

/**
 * @brief Add an additional signer to a builder
 *
 * The first signer is set with jwt_builder_setkey(); this adds further ones for
 * a multi-signature JWS JSON Serialization. The second signer automatically
 * promotes the format to ::JWT_FORMAT_JSON_GENERAL. Each signature signs over
 * its own protected header and the shared payload, so signers may use different
 * algorithms (e.g. RS256 and ES256). ``alg`` must not be ::JWT_ALG_NONE.
 *
 * @param builder Pointer to a builder object
 * @param alg A valid ::jwt_alg_t type (not ::JWT_ALG_NONE)
 * @param key A JWK private key matching @p alg
 * @return A borrowed ::jwt_signature_t handle (owned by the builder), or NULL
 *  on error with the error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
jwt_signature_t *jwt_builder_add_signature(jwt_builder_t *builder, jwt_alg_t alg,
					   const jwk_item_t *key);

/**
 * @brief Add a member to a signature's protected header
 *
 * The value is parsed as JSON. The member is integrity-protected (it is part
 * of the bytes this signature signs over) and is the right place for a
 * per-signer ``kid``. Library-managed names (``alg``) and duplicates are
 * rejected.
 *
 * @param signature A handle from jwt_builder_add_signature()
 * @param key The header parameter name
 * @param value_json The value as a JSON string
 * @return 0 on success, non-zero otherwise
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_signature_add_protected_json(jwt_signature_t *signature,
				     const char *key, const char *value_json);

/**
 * @brief Add a member to a signature's unprotected header
 *
 * The value is parsed as JSON. The member is NOT integrity-protected and is
 * only emitted in the JSON serializations (@rfc{7515,7.2.1}). It must be
 * disjoint from this signature's protected header.
 *
 * @param signature A handle from jwt_builder_add_signature()
 * @param key The header parameter name
 * @param value_json The value as a JSON string
 * @return 0 on success, non-zero otherwise
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_signature_add_header_json(jwt_signature_t *signature,
				  const char *key, const char *value_json);

/**
 * @brief Sign an opaque (non-claims) payload
 *
 * Sets a raw payload to be signed verbatim instead of JSON claims, for a
 * generic JWS (RFC 7515) — for example RFC 7797 unencoded payloads or a
 * detached signature over an arbitrary document (JAdES). This is mutually
 * exclusive with claims: when a raw payload is set it is used and any claims
 * are ignored. Pass @p data as NULL (or @p len 0) to clear it and return to
 * the claims model. The bytes are copied.
 *
 * @param builder Pointer to a builder object
 * @param data The payload bytes (copied), or NULL to clear
 * @param len The payload length in bytes
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_setpayload(jwt_builder_t *builder, const unsigned char *data,
			   size_t len);

/**
 * @brief Select base64url or unencoded payload (RFC 7797)
 *
 * With @p b64 nonzero (the default) the payload is base64url-encoded as usual.
 * With @p b64 zero, @rfc{7797} unencoded payloads are produced: ``"b64":false``
 * is emitted in the protected header, ``"b64"`` is added to ``"crit"``, and the
 * signature is computed over the **raw** payload bytes. Requires a raw payload
 * (jwt_builder_setpayload()), since RFC 7797 forbids the option for JWTs.
 *
 * @param builder Pointer to a builder object
 * @param b64 Nonzero for base64url (default), zero for an unencoded payload
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_setb64(jwt_builder_t *builder, int b64);

/**
 * @brief Detach the payload from the output
 *
 * With @p detached nonzero, the produced token omits the payload (an empty
 * payload part in the Compact form, no ``"payload"`` member in the JSON forms).
 * The verifier must supply the payload out-of-band with
 * jwt_checker_verify_detached(). Orthogonal to jwt_builder_setb64().
 *
 * @param builder Pointer to a builder object
 * @param detached Nonzero to omit the payload from the output
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_set_detached(jwt_builder_t *builder, int detached);

/**
 * @brief Set the token media type ("typ" header)
 *
 * A convenience setter for the ``"typ"`` header parameter, naming the token's
 * media type — e.g. ``"at+jwt"`` (RFC 9068), ``"dpop+jwt"``, ``"secevent+jwt"``.
 * Equivalent to setting the ``"typ"`` header directly. Pair it with
 * jwt_checker_expect_typ() on the verifying side.
 *
 * @param builder Pointer to a builder object
 * @param typ The media type string, or NULL to clear it
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_settyp(jwt_builder_t *builder, const char *typ);

/**
 * @brief Set IssuedAt usage on builder
 *
 * By default, the builder will set the ``iat`` claim to all tokens. You can
 * enable or disable this using this function.
 *
 * @param builder Pointer to a builder object
 * @param enable 0 to disable, any other value to enable
 * @return Previous value (0 or 1), or -1 on error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_builder_enable_iat(jwt_builder_t *builder, int enable);

/**
 * @brief Set a callback for generating tokens
 *
 * When generating a token, this callback will be run after jwt_t has been
 * created, but before the token is encoded. During this, the callback can set,
 * change, or remove claims and header attributes. It can also use the
 * jwt_value_t structure to set a key and alg to use when signing the token.
 *
 * The ctx value is also passed to the callback as part of the jwt_value_t
 * struct.
 *
 * @note Calling this with a NULL cb param and a new ctx param after already
 * setting the callback will allow updating the ctx passed to the callback.
 * Calling with both values as NULL will disable the callback completely.
 *
 * @param builder Pointer to a builder object
 * @param cb Pointer to a callback function
 * @param ctx Pointer to data to pass to the callback function
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_builder_setcb(jwt_builder_t *builder, jwt_callback_t cb, void *ctx);

/**
 * @brief Set a callback to generate the ``jti`` (JWT ID) claim (@rfc{7519,4.1.7})
 *
 * When set, the callback is run during generation to produce a unique ``jti``
 * for each token. The string it returns is set as the ``"jti"`` claim and then
 * freed by LibJWT; returning NULL aborts generation. The application is
 * responsible for guaranteeing uniqueness (the RFC requires a negligible
 * collision probability, even across issuers).
 *
 * The ctx is passed to the callback via the @ref jwt_config_t structure.
 *
 * @note Calling this with a NULL cb and a new ctx updates the ctx. Calling with
 * both NULL disables the callback.
 *
 * @param builder Pointer to a builder object
 * @param cb Pointer to a jti generation callback
 * @param ctx Pointer to data to pass to the callback
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwt_builder_setjti(jwt_builder_t *builder, jwt_jti_gen_cb_t cb, void *ctx);

/**
 * @brief Retrieve the callback context that was previously set
 *
 * This is useful for accessing the context that was previously passed in the
 * setcb function.
 *
 * @param builder Pointer to a builder object
 * @return Pointer to the context or NULL
 * @since 3.0.0
 */
JWT_EXPORT
void *jwt_builder_getctx(jwt_builder_t *builder);

/**
 * @brief Mark a header parameter as critical (@rfc{7515,4.1.11})
 *
 * Registers a header parameter name to be listed in the ``crit`` (Critical)
 * header parameter of generated tokens. Use this when your application adds a
 * custom (extension) header that a recipient MUST understand and process; per
 * RFC 7515, a recipient that does not understand a listed parameter MUST reject
 * the token.
 *
 * Call this once for each name. The named header parameter must be present in
 * the header when the token is generated (typically set in your callback), and
 * it must not be a Header Parameter name defined by RFC 7515 or JWA (such as
 * ``alg`` or ``typ``); otherwise generation will fail. If no names are
 * registered, no ``crit`` header is emitted.
 *
 * @param builder Pointer to a builder object
 * @param header Name of the header parameter to mark as critical
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwt_builder_setcrit(jwt_builder_t *builder, const char *header);

/**
 * @brief Generate a token
 *
 * The result of this function is to generate a string containing a JWT. A
 * token is represetned by 3 parts: ``header``.``payload``.``sig``. Each part is
 * Base64url Encoded. An example would be:
 *
 * @code
 * eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzY0MzI0MzR9.iDn6N9JsAdUPF11ow0skIfc9eJc2wGRIq30RSRZ8_68
 * @endcode
 *
 * When decoded, the header and payload would look like this (excluding the
 * signature block)::
 *
 * @code
 * {"alg":"HS256","typ":"JWT"}.{"iat":1736432434}
 * @endcode
 *
 * If pretty printed:
 *
 * @code
 * {
 *    "alg": "HS256",
 *    "typ": "JWT"
 * }
 * .
 * {
 *    "iat": 1736432434
 * }
 * @endcode
 *
 * The signature block is a cryptographic hash. Its length and format is
 * dependent on the algorithm being used.
 *
 * A simple usage with no signature or payload would be:
 *
 * @code
 * jwt_builder_t *builder = NULL;
 *
 * builder = jwt_builder_new();
 *
 * if (builder) {
 *     char *out = jwt_builder_generate(builder);
 *
 *     if (out) {
 *         printf("%s\n", out);
 *         free(out);
 *     }
 * }
 *
 * jwt_builder_free(builder);
 * @endcode
 *
 * @note If you set a callback for this builder, this is when it will be called.
 *
 * @param builder Pointer to a builder object
 * @return A string containing a JWT. Caller is respondible for freeing the
 *  memory for this string. On error, NULL is returned and error is set in
 *  the builder object.
 * @since 3.0.0
 */
JWT_EXPORT
char *jwt_builder_generate(jwt_builder_t *builder);

/**
 * @}
 * @noop jwt_builder_grp
 */

/**
 * @defgroup jwt_checker_grp Checker
 *
 * @brief Verify and validate JWT tokens
 *
 * Validating a JWT involves decoding the Base64url parts of the JWT then
 * verifying claims and the signature hash. The checker object allows you to
 * configure how you want to perform these steps so you can easily process
 * tokens with one simple call.
 * @{
 */

/**
 * @brief Opaque Checker object
 * @since 3.0.0
 */
typedef struct jwt_checker jwt_checker_t;

/**
 * @brief Function to create a new checker instance
 *
 * @return Pointer to a checker object on success, NULL on failure
 * @since 3.0.0
 */
JWT_EXPORT
jwt_checker_t *jwt_checker_new(void);

/**
 * @brief Frees a previously created checker object
 *
 * @param checker Pointer to a checker object
 * @since 3.0.0
 */
JWT_EXPORT
void jwt_checker_free(jwt_checker_t *checker);

#if defined(__GNUC__) || defined(__clang__) || defined(_DOXYGEN)
/**
 * @brief Helper function to free a checker and set the pointer to NULL
 *
 * This is mainly to use with the jwt_checker_auto_t type. Example usage:
 *
 * @code
 * int run_check (const char *token)
 * {
 *     jwt_checker_auto_t *checker = NULL; // This is important to set to NULL
 *
 *     checker = jwt_checker_new();
 *     // Do some things
 *
 *     return 0; // checker is freed here
 * }
 * @endcode
 *
 * @param Pointer to a pointer for a jwt_checker_t object
 * @since 3.0.0
 */
static inline void jwt_checker_freep(jwt_checker_t **checker) {
        if (checker) {
                jwt_checker_free(*checker);
                *checker = NULL;
        }
}
/**
 * @brief A jwt_checker_t pointer that is freed automatically at scope exit
 *
 * Declares a jwt_checker_t pointer carrying the GCC/Clang ``cleanup``
 * attribute so jwt_checker_free() is invoked on it automatically when the
 * variable goes out of scope. Initialize it where you declare it.
 *
 * @since 3.0.0
 */
#define jwt_checker_auto_t jwt_checker_t \
        __attribute__((cleanup(jwt_checker_freep)))
#endif

/**
 * @brief Checks error state of checker object
 *
 * @param checker Pointer to a checker object
 * @return 0 if no errors exist, non-zero otherwise
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_error(const jwt_checker_t *checker);

/**
 * @brief Get the error message contained in a checker object
 *
 * @param checker Pointer to a checker object
 * @return Pointer to a string with the error message. Can be an empty string
 *  if there is no error. Never returns NULL.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwt_checker_error_msg(const jwt_checker_t *checker);

/**
 * @brief Clear error state in a checker object
 *
 * @param checker Pointer to a checker object
 * @since 3.0.0
 */
JWT_EXPORT
void jwt_checker_error_clear(jwt_checker_t *checker);

/**
 * @brief Sets a key and algorithm for a checker
 *
 * See @ref jwt_builder_setkey for detailed information.
 *
 * @param checker Pointer to a checker object
 * @param alg A valid jwt_alg_t type
 * @param key A JWK key object
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_setkey(jwt_checker_t *checker, const jwt_alg_t alg, const
		       jwk_item_t *key);

/**
 * @brief Multi-signature verification policy
 *
 * Governs how jwt_checker_verify() decides on a JWS JSON Serialization that
 * carries more than one signature (@rfc{7515,7.2} leaves this to the
 * application). It has no effect on a Compact or single-signature token.
 *
 * @since 3.6.0
 */
typedef enum {
	JWT_VERIFY_POLICY_ANY = 0,	/**< Accept if >=1 signature verifies	*/
	JWT_VERIFY_POLICY_ALL,		/**< Accept only if every signature does	*/
} jwt_verify_policy_t;

/**
 * @brief Set a keyring and policy for multi-signature verification
 *
 * Supplies a set of candidate keys (a JWKS) instead of the single key set by
 * jwt_checker_setkey(), so a JWS JSON Serialization with multiple signatures
 * can be verified. A signature naming a ``kid`` is matched to that key in the
 * ring; a keyless signature is tried against every compatible key. Each
 * candidate is held to the usual algorithm/key-type binding.
 *
 * Under ::JWT_VERIFY_POLICY_ANY (the default and the generalization of the
 * single-key behavior) the token is accepted if at least one signature
 * verifies; under ::JWT_VERIFY_POLICY_ALL every signature in the token must
 * verify. The keyring is borrowed: the caller retains ownership and must keep
 * it valid for the lifetime of the checker. Setting a keyring and setting a
 * single key are mutually exclusive; the last call wins.
 *
 * @param checker Pointer to a checker object
 * @param keyring A JWKS of candidate keys (borrowed, not freed by the checker)
 * @param policy A ::jwt_verify_policy_t value
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_checker_setkeyring(jwt_checker_t *checker, const jwk_set_t *keyring,
			   jwt_verify_policy_t policy);

/**
 * @brief Require a specific token media type ("typ" header)
 *
 * When set, jwt_checker_verify() rejects a token whose ``"typ"`` header does not
 * match @p typ. The comparison is case-insensitive and tolerates the optional
 * ``application/`` prefix (RFC 6838), so ``expect_typ(c, "at+jwt")`` accepts both
 * ``"at+jwt"`` and ``"application/at+jwt"``. This is the standardized
 * cross-JWT-confusion defense (@rfc{8725} §3.11).
 *
 * @param checker Pointer to a checker object
 * @param typ The required media type, or NULL to clear the requirement
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_checker_expect_typ(jwt_checker_t *checker, const char *typ);

/**
 * @brief Set an allowlist of acceptable algorithms
 *
 * Restricts the algorithms jwt_checker_verify() will accept to the given set,
 * checked before any signature work (@rfc{8725}). Useful when verifying against
 * a keyring (jwt_checker_setkeyring()) where several algorithms are acceptable,
 * e.g. ``{JWT_ALG_RS256, JWT_ALG_ES256}``. A token whose ``"alg"`` is not in the
 * set is rejected, which also blocks an ``alg:none`` downgrade. Passing @p n as
 * 0 (or @p algs as NULL) clears the allowlist.
 *
 * @param checker Pointer to a checker object
 * @param algs An array of acceptable ::jwt_alg_t values (copied)
 * @param n The number of entries in @p algs
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_checker_setalgs(jwt_checker_t *checker, const jwt_alg_t *algs, size_t n);

/**
 * @brief Set a callback for generating tokens
 *
 * When verifying a token, this callback will be run after jwt_t has been
 * parsed, but before the token is verified (including signature
 * verification). During this, the callback should only inspect the header or
 * claims in the JWT. Any attempts to make changes to the jwt_t object will not
 * change the rest of the process.
 *
 * The callback can also set the key and algorithm used to verify the signature.
 * If the callback returns non-zero, then processing will stop and return an
 * error.
 *
 * The ctx value is also passed to the callback as part of the jwt_value_t
 * struct.
 *
 * @note Calling this with a NULL cb param and a new ctx param after already
 * setting the callback will allow updating the ctx passed to the callback.
 * Calling with both values as NULL will disable the callback completely.
 *
 * @param checker Pointer to a checker object
 * @param cb Pointer to a callback function
 * @param ctx Pointer to data to pass to the callback function
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_setcb(jwt_checker_t *checker, jwt_callback_t cb, void *ctx);

/**
 * @brief Set a callback to verify the ``jti`` (JWT ID) claim (@rfc{7519,4.1.7})
 *
 * When set, verification reads the token's ``"jti"`` claim and passes it to the
 * callback, which returns 0 to accept or non-zero to reject the token. This is
 * where an application implements replay protection against its own id pool
 * (look the id up and consume it). When this callback is set, a token that has
 * no ``"jti"`` claim is rejected.
 *
 * The ctx is passed to the callback via the @ref jwt_config_t structure.
 *
 * @note Calling this with a NULL cb and a new ctx updates the ctx. Calling with
 * both NULL disables the callback.
 *
 * @param checker Pointer to a checker object
 * @param cb Pointer to a jti verification callback
 * @param ctx Pointer to data to pass to the callback
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.4.0
 */
JWT_EXPORT
int jwt_checker_setjti(jwt_checker_t *checker, jwt_jti_check_cb_t cb, void *ctx);

/**
 * @brief Retrieve the callback context that was previously set
 *
 * This is useful for accessing the context that was previously passed in the
 * setcb function.
 *
 * @param checker Pointer to a checker object
 * @return Pointer to the context or NULL
 * @since 3.0.0
 */
JWT_EXPORT
void *jwt_checker_getctx(jwt_checker_t *checker);

/**
 * @brief Declare a critical header parameter as understood (@rfc{7515,4.1.11})
 *
 * Per RFC 7515, if a token's ``crit`` (Critical) header parameter lists a
 * header name, the recipient MUST understand and process that header or else
 * reject the token. LibJWT understands no extension header parameters on its
 * own, so by default any token carrying a ``crit`` header will fail
 * verification.
 *
 * Use this function to declare each extension header parameter that your
 * application is prepared to handle (typically inspected in your verify
 * callback). During verification, every name listed in ``crit`` must both be
 * present in the header and have been declared here; otherwise the token is
 * rejected.
 *
 * @param checker Pointer to a checker object
 * @param header Name of the critical header parameter the application understands
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.4.0
 */
JWT_EXPORT
int jwt_checker_understands(jwt_checker_t *checker, const char *header);

/**
 * @brief Verify a token
 *
 * @note If you set a callback for this checker, this is when it will be called.
 *
 * @param checker Pointer to a checker object
 * @param token A string containing a token to be verified
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_verify(jwt_checker_t *checker, const char *token);

/**
 * @brief Number of signatures in the last verified token
 *
 * After jwt_checker_verify(), returns how many signatures the token carried
 * (1 for a Compact or Flattened token, N for a General one, 0 if verification
 * failed before the signatures were parsed).
 *
 * @param checker Pointer to a checker object
 * @return The signature count of the last token
 * @since 3.6.0
 */
JWT_EXPORT
unsigned int jwt_checker_sig_count(const jwt_checker_t *checker);

/**
 * @brief Whether a given signature of the last token verified
 *
 * After jwt_checker_verify(), reports per-signature results. Useful under
 * ::JWT_VERIFY_POLICY_ANY to learn which signature(s) passed.
 *
 * @param checker Pointer to a checker object
 * @param index A signature index in ``[0, jwt_checker_sig_count())``
 * @return 1 if signature @p index verified against a keyring key, 0 otherwise
 *  (including an out-of-range index)
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_checker_sig_verified(const jwt_checker_t *checker, unsigned int index);

/**
 * @brief The key a given signature of the last token verified against
 *
 * @param checker Pointer to a checker object
 * @param index A signature index in ``[0, jwt_checker_sig_count())``
 * @return The keyring key that verified signature @p index, or NULL if it did
 *  not verify or the index is out of range. Borrowed from the keyring; do not
 *  free.
 * @since 3.6.0
 */
JWT_EXPORT
const jwk_item_t *jwt_checker_sig_key(const jwt_checker_t *checker,
				      unsigned int index);

/**
 * @brief Verify a token whose payload was detached
 *
 * Verifies a token produced with jwt_builder_set_detached() (or any JWS with a
 * detached payload), supplying the payload out-of-band. Works for both
 * base64url and @rfc{7797} unencoded (``"b64":false``) payloads; the signing
 * input is reconstructed from @p payload according to the token's ``"b64"``
 * header. As with jwt_checker_verify(), an unencoded payload is accepted only
 * if ``"b64"`` is present in the token's ``"crit"`` header (RFC 7797 §6).
 *
 * @param checker Pointer to a checker object
 * @param token A string containing the (detached) token to verify
 * @param payload The out-of-band payload bytes
 * @param len The payload length in bytes
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_checker_verify_detached(jwt_checker_t *checker, const char *token,
				const unsigned char *payload, size_t len);

/**
 * @}
 * @noop jwt_checker_grp
 */

/**
 * @defgroup jwt_claims_grp Claims and Headers
 *
 * @brief Get and set JWT claims and header parameters
 *
 * Working with claims and header elements across checker and builder
 * objects is similar, but the usage for it is not.
 *
 * @{
 */

/**
 * @defgroup jwt_claims_helpers_grp Utility Functions
 *
 * @brief Set up a jwt_value_t for getting and setting claims and headers
 * @{
 */

/**
 * @defgroup jwt_helpers_get_grp Getters
 *
 * @brief Set up a jwt_value_t to retrieve a claim or header value
 *
 * When getting a value, you must set type and name. On a successful return, the
 * the value specific to the type will be filled in. Common error responses for
 * this function are JWT_VALUE_ERR_NOEXIST when the name does not exist, and
 * JWT_VALUE_ERR_TYPE, when the named object is not of the type you requested
 * (e.g. you requested a string, but it's an integer value).
 *
 * @remarks When getting a JSON value, you can set value.name = NULL, in which
 *  case the entire header is returned. Also, the resulting value.json_val
 *  will be using allocated memory and must be freed by the caller.
 *
 * @note Normally JSON is retrieved in compact form. If you set
 *  jwt_value_t.pretty, then you will get a tabbed format suitable for human
 *  viewing. This must be set after calling jwt_set_GET_JSON().
 *
 * @code
 *     jwt_value_error_t ret;
 *     jwt_value_t jval;
 *
 *     jwt_set_GET_INT(&jval, "h1");
 *     ret = jwt_builder_claim_get(builder, &jval);
 *     if (ret == JWT_VALUE_ERR_NONE)
 *         printf("h1 = %d\n", jval.int_val);
 * @endcode
 *
 * @{
 */

/**
 * @brief Setup a jwt_value_t to get an integer value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_GET_INT(__v, __n) ({	\
	(__v)->type=JWT_VALUE_INT;	\
	(__v)->name=(__n);(__v)->int_val=0;(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to get a string value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_GET_STR(__v, __n) ({	\
	(__v)->type=JWT_VALUE_STR;	\
	(__v)->name=(__n);(__v)->str_val=NULL;(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to get a boolean value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_GET_BOOL(__v, __n) ({	\
	(__v)->type=JWT_VALUE_BOOL;	\
	(__v)->name=(__n);(__v)->bool_val=0;(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to get a JSON string
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_GET_JSON(__v, __n) ({			\
	(__v)->type=JWT_VALUE_JSON;(__v)->pretty=0;	\
	(__v)->name=(__n);(__v)->json_val=NULL;(__v)->error=0;\
	(__v);})

/**
 * @}
 * @noop jwt_helpers_get_grp
 */

/**
 * @defgroup jwt_helpers_set_grp Setters
 *
 * @brief Set up a jwt_value_t to store a claim or header value
 *
 * When setting a value, you must set the type, name, and the specific val for
 * the type. If the value already exists, then the function will return
 * JWT_VALUE_ERR_EXISTS and value.error will be set the same. If value.replace
 * is non-zero, then any existing value will be overwritten.
 *
 * @remarks When setting a JSON value, you can set value.name = NULL, in which case
 *  the entire header will be set to the JSON string pointed to by
 *  value.json_val. If value.replace is not set, only values that do not already
 *  exist will be set. If replace is set, then existing values will also be
 *  updated. There is no indication of which values are or aren't updated in
 *  either case.
 *
 * @note The replace flag must be set after calling jwt_set_SET_*() macro, as
 *  the macros will reset it back to 0.
 *
 * @code
 *     jwt_value_error_t ret;
 *     jwt_value_t jval;
 *
 *     jwt_set_SET_STR(&jval, "iss", "foo.example.com");
 *     ret = jwt_builder_header_set(jwt, &jval);
 *
 *     if (ret == JWT_VALUE_ERR_NONE)
 *         printf("iss updated to: %s\n", jval.str_val);
 * @endcode
 *
 * @{
 */

/**
 * @brief Setup a jwt_value_t to set an integer value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @param __x Value to set
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_SET_INT(__v, __n, __x) ({		\
	(__v)->type=JWT_VALUE_INT;(__v)->replace=0;	\
	(__v)->name=(__n);(__v)->int_val=(__x);(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to set a string value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @param __x Value to set
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_SET_STR(__v, __n, __x) ({		\
	(__v)->type=JWT_VALUE_STR;(__v)->replace=0;	\
	(__v)->name=(__n);(__v)->str_val=(__x);(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to set a boolean value
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @param __x Value to set
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_SET_BOOL(__v, __n, __x) ({		\
	(__v)->type=JWT_VALUE_BOOL;(__v)->replace=0;	\
	(__v)->name=(__n);(__v)->bool_val=(__x);(__v)->error=0;\
	(__v);})

/**
 * @brief Setup a jwt_value_t to set a JSON string
 *
 * @param __v Pointer to a jwt_value_t object
 * @param __n Name of the value
 * @param __x Value to set
 * @return No return value
 * @since 3.0.0
 */
#define jwt_set_SET_JSON(__v, __n, __x) ({			\
	(__v)->type=JWT_VALUE_JSON;(__v)->replace=0;		\
	(__v)->name=(__n);(__v)->json_val=(__x);(__v)->error=0;	\
	(__v);})

/**
 * @}
 * @noop jwt_helpers_set_grp
 */

/**
 * @}
 * @noop jwt_claims_helpers_grp
 */

/**
 * @defgroup jwt_claims_builder_grp Builder Functions
 *
 * @brief Get, set, and delete claims and headers on a builder object
 *
 * For the builder function, you can create a set of values in the header and
 * payload that will be copied verbatim to any token generated from it. The
 * special claims, ``nbf`` and ``exp``, can be handled more dynamically by
 * LibJWT, if they are enabled (see jwt_builder_time_offset).
 *
 * For any claims that you want to handle on a per token basis (e.g. you may
 * want a different ``sub`` depending on the user context), this can be done in
 * a callback on the jwt_t object.
 *
 * These functions rely on the @ref jwt_helpers_set_grp macros to better handle
 * the data being passed to them.
 *
 * @{
 */

/**
 * @brief Set a header in a builder object
 *
 * @param builder Pointer to a builder object
 * @param value Pointer to a jwt_value_t object representing the value to set
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_header_set(jwt_builder_t *builder, jwt_value_t
					 *value);

/**
 * @brief Get a header from a builder object
 *
 * @param builder Pointer to a builder object
 * @param value Pointer to a jwt_value_t object representing the value to get
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error. Also, the relevant value.*_val will be set on success.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_header_get(jwt_builder_t *builder, jwt_value_t
					 *value);

/**
 * @brief Delete a header from a builder object
 *
 * @param builder Pointer to a builder object
 * @param header Name of the header delete
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_header_del(jwt_builder_t *builder, const char
					 *header);

/**
 * @brief Set a claim in a builder object
 *
 * @param builder Pointer to a builder object
 * @param value Pointer to a jwt_value_t object representing the value to set
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_claim_set(jwt_builder_t *builder, jwt_value_t
					*value);

/**
 * @brief Get a claim from a builder object
 *
 * @param builder Pointer to a builder object
 * @param value Pointer to a jwt_value_t object representing the value to get
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error. Also, the relevant value.*_val will be set on success.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_claim_get(jwt_builder_t *builder, jwt_value_t
					*value);

/**
 * @brief Delete a header from a builder object
 *
 * @param builder Pointer to a builder object
 * @param claim Name of the claim delete
 * @return JWT_VALUE_ERR_NONE on success, one of the jwt_value_error_t return
 *  on error.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_builder_claim_del(jwt_builder_t *builder, const char
					*claim);

/**
 * @brief Disable, or enable and set the ``nbf`` or ``exp`` time offsets
 *
 * The time offset is in seconds and will be added to ``now`` when a token is
 * created. Negative values are not allowed. Setting the secs to 0 or less will
 * disable adding the specified claim to the token.
 *
 * @param builder Pointer to a builder object
 * @param claim One of JWT_CLAIM_NBF or JWT_CLAIM_EXP
 * @param secs Seconds of offset to add to ``now`` when generating the
 *  specified claim
 * @return 0 on success, any other value for an error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_builder_time_offset(jwt_builder_t *builder, jwt_claims_t claim,
			    time_t secs);

/**
 * @}
 * @noop jwt_claims_builder_grp
 */

/**
 * @defgroup jwt_claims_checker_grp Checker Functions
 *
 * @brief Get, set, and delete the claims a checker validates
 *
 * For a checker object, claims will be used to verify the token. This
 * verification is very simplistic and only supports standards-defined
 * claims like ``nbf``, ``iss``, etc. Even for some of these, LibJWT can
 * only perform simple time or string comparison. For example, if you wanted
 * to accept tokens from multiple issuers, you would need to handle that
 * yourself, most likely in a callback.
 *
 * This is a list of the claims that LibJWT can check on its own, and the
 * method that is used to decide success:
 *
 * Claim   | Type            | Comparison for Validation
 * ------- | --------------- | -----------------------------
 * ``exp`` | Timestamp       | ``exp`` > (now + leeway)
 * ``nbf`` | Timestamp       | ``nbf`` <= (now - leeway)
 * ``iss`` | String          | !strcmp(``iss``, ``userval``)
 * ``aud`` | String or Array | ``userval`` equals ``aud``, or is among its elements
 * ``sub`` | String          | !strcmp(``sub``, ``userval``)
 *
 * @note Validation is "validate if present": enabling a check (e.g.
 * ``JWT_CLAIM_EXP``) only fails a token when the claim @b is present and does
 * not satisfy the comparison above. A token that @b omits the claim passes the
 * check. In particular, enabling ``JWT_CLAIM_EXP`` does @b not by itself
 * require that a token carry an ``exp``; if you must reject tokens lacking a
 * given claim, enforce that in a callback.
 *
 * @note Per @rfc{7519,4.1.3}, ``aud`` may be a single string or an array of
 * strings; the token is accepted when your configured audience matches the
 * string or appears among the array elements.
 *
 * @note The checker object does not evaluate any values in the header with
 * the exception of the ``alg`` element when validating a token. Anything you
 * need to do there can be done in a callback with the jwt_t.
 *
 * @{
 */

/**
 * @brief Get the value of a validation claim
 *
 * @param checker Pointer to a checker object
 * @param type One of JWT_CLAIM_ISS, JWT_CLAIM_AUD, or JWT_CLAIM_SUB
 * @return A string representation of the claim, or NULL if it isn't set
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwt_checker_claim_get(jwt_checker_t *checker, jwt_claims_t type);

/**
 * @brief Set the value of a validation claim
 *
 * @param checker Pointer to a checker object
 * @param type One of JWT_CLAIM_ISS, JWT_CLAIM_AUD, or JWT_CLAIM_SUB
 * @param value A string to set as the new value of the validation
 * @return 0 on success, any other value is an error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_claim_set(jwt_checker_t *checker, jwt_claims_t type,
			  const char *value);

/**
 * @brief Delete the value of a validation claim
 *
 * @param checker Pointer to a checker object
 * @param type One of JWT_CLAIM_ISS, JWT_CLAIM_AUD, or JWT_CLAIM_SUB
 * @return 0 on success, any other value is an error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_claim_del(jwt_checker_t *checker, jwt_claims_t type);

/**
 * @brief Setup the exp or nbf claim leeway values
 *
 * This allows you to set a leeway for exp and nbf claims to account for any
 * skew. The value is in seconds.
 *
 * To disable either one, set the secs to -1.
 *
 * @param checker Pointer to a checker object
 * @param claim One of JWT_CLAIM_NBF or JWT_CLAIM_EXP
 * @param secs The number of seconds of leeway to account for being valid
 * @return 0 on success, any other value is an error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_checker_time_leeway(jwt_checker_t *checker, jwt_claims_t claim,
			    time_t secs);

/**
 * @}
 * @noop jwt_claims_checker_grp
 */

/**
 * @defgroup jwt_object_grp JWT Functions
 *
 * @brief Get and set claims and headers on a jwt_t during a callback
 *
 * For most usage, setting values in the builder object is enough to provide
 * all the information you would like set in a JWT token. However, if some
 * information is dynamic, meaning it is only known at the time the token is
 * created, then you can provide this during the builder callback on the jwt_t
 * object.
 *
 * When verifying a token, the checker callback should not modify the jwt_t
 * object at all. Access to the jwt_t is provided only to allow additional
 * validation beyond LibJWT's internal checks.
 * @{
 */

/**
 * @brief Set a value in the header of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param value A jwt_value_t structure with relevant actions filled in
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success. The
 *  value.error field will match this return value.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_header_set(jwt_t *jwt, jwt_value_t *value);

/**
 * @brief Get a value from the header of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param value A jwt_value_t structure with relevant actions filled in
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success. The
 *  value.error field will match this return value.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_header_get(jwt_t *jwt, jwt_value_t *value);

/**
 * @brief Delete a value from the header of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param header The name of the header to delete, or NULL to clear the entire
 *  header
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_header_del(jwt_t *jwt, const char *header);

/**
 * @brief Set a value in the claims of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param value A jwt_value_t structure with relevant actions filled in
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success. The
 *  value.error field will match this return value.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_claim_set(jwt_t *jwt, jwt_value_t *value);

/**
 * @brief Get a value from the claims of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param value A jwt_value_t structure with relevant actions filled in
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success. The
 *  value.error field will match this return value.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_claim_get(jwt_t *jwt, jwt_value_t *value);

/**
 * @brief Delete a value from the claims of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param claim The name of the claim to delete, or NULL to clear all claims
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_value_error_t jwt_claim_del(jwt_t *jwt, const char *claim);

/**
 * @brief Set the "cnf" (confirmation) claim to a key thumbprint
 *
 * @rfc{7800} @rfc{9449,6}
 *
 * Sets @c "cnf" to a single @c "jkt" member holding the RFC 7638 SHA-256 JWK
 * thumbprint of @p key (the DPoP confirmation method). Any existing @c "cnf"
 * is replaced, so the object always carries exactly one confirmation member.
 *
 * @param builder Pointer to a builder object
 * @param key The proof-of-possession public key to bind the token to
 * @return 0 on success, non-zero on error
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_setcnf_jkt(jwt_builder_t *builder, const jwk_item_t *key);

/**
 * @brief Set the "cnf" (confirmation) claim to an embedded JWK
 *
 * @rfc{7800,3.2}
 *
 * Sets @c "cnf" to a single @c "jwk" member holding the public JWK of @p key.
 * Only public parameters are embedded. Any existing @c "cnf" is replaced.
 *
 * @param builder Pointer to a builder object
 * @param key The proof-of-possession public key to embed
 * @return 0 on success, non-zero on error
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_setcnf_jwk(jwt_builder_t *builder, const jwk_item_t *key);

/**
 * @brief Set the "cnf" (confirmation) claim to a single string member
 *
 * @rfc{7800}
 *
 * Sets @c "cnf" to a single member named @p member with string value @p value
 * -- e.g. @c "kid" (RFC 7800), @c "x5t#S256" (RFC 8705 mTLS), or @c "jku". Any
 * existing @c "cnf" is replaced, so the object always carries exactly one
 * confirmation member.
 *
 * @param builder Pointer to a builder object
 * @param member The confirmation member name (e.g. @c "kid", @c "x5t#S256")
 * @param value The member's string value
 * @return 0 on success, non-zero on error
 * @since 3.6.0
 */
JWT_EXPORT
int jwt_builder_setcnf(jwt_builder_t *builder, const char *member,
		       const char *value);

/**
 * @brief Read a string-valued "cnf" (confirmation) member from a token
 *
 * @rfc{7800}
 *
 * Returns the value of @c cnf.@p member (e.g. @c "jkt", @c "kid",
 * @c "x5t#S256") for a verified token. Because a verifier obtains the @ref
 * jwt_t inside its jwt_checker_setcb() callback, this is where you call it to
 * confirm a presented proof-of-possession key.
 *
 * @param jwt Pointer to a jwt_t token
 * @param member The confirmation member name to read
 * @return A newly allocated, nil-terminated string the caller must free with
 *   free(), or NULL if @c cnf or the member is absent or not a string
 * @since 3.6.0
 */
JWT_EXPORT
char *jwt_get_cnf(const jwt_t *jwt, const char *member);

/**
 * @}
 * @noop jwt_object_grp
 */

/**
 * @}
 * @noop jwt_claims_grp
 */

/**
 * @defgroup jwt_alg_grp Algorithms
 *
 * @brief Convert between algorithm types and their string names
 *
 * Utility functions to convert between string and type for ``alg``
 * @{
 */

/**
 * Convert alg type to it's string representation.
 *
 * Returns a string that matches the alg type provided.
 *
 * @param alg A valid jwt_alg_t specifier.
 * @returns Returns a string (e.g. "RS256") matching the alg or NULL for
 *     invalid alg.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwt_alg_str(jwt_alg_t alg);

/**
 * Convert alg string to type.
 *
 * Returns an alg type based on the string representation.
 *
 * @rfc{7518,3.1}
 *
 * @param alg A valid string for algorithm type (e.g. "RS256").
 * @returns Returns a @ref jwt_alg_t matching the string
 *  or @ref JWT_ALG_INVAL if no  matches were found.
 *
 * @note This only works for algorithms that LibJWT supports or knows about.
 * @since 3.0.0
 */
JWT_EXPORT
jwt_alg_t jwt_str_alg(const char *alg);

/**
 * Convert a JWE key management alg type to its string representation.
 *
 * @param alg A valid jwe_key_alg_t specifier.
 * @returns Returns a string (e.g. "RSA-OAEP") matching the alg or NULL for
 *     an invalid alg.
 * @since 3.4.0
 */
JWT_EXPORT
const char *jwe_alg_str(jwe_key_alg_t alg);

/**
 * Convert a JWE key management alg string to type.
 *
 * @rfc{7518,4.1}
 *
 * @param alg A valid string for a JWE key management algorithm (e.g. "A128KW").
 * @returns Returns a @ref jwe_key_alg_t matching the string or
 *  @ref JWE_ALG_INVAL if no matches were found.
 * @since 3.4.0
 */
JWT_EXPORT
jwe_key_alg_t jwe_str_alg(const char *alg);

/**
 * Convert a JWE content encryption enc type to its string representation.
 *
 * @param enc A valid jwe_enc_t specifier.
 * @returns Returns a string (e.g. "A256GCM") matching the enc or NULL for
 *     an invalid enc.
 * @since 3.4.0
 */
JWT_EXPORT
const char *jwe_enc_str(jwe_enc_t enc);

/**
 * Convert a JWE content encryption enc string to type.
 *
 * @rfc{7518,5.1}
 *
 * @param enc A valid string for a JWE content encryption algorithm
 *  (e.g. "A256GCM").
 * @returns Returns a @ref jwe_enc_t matching the string or
 *  @ref JWE_ENC_INVAL if no matches were found.
 * @since 3.4.0
 */
JWT_EXPORT
jwe_enc_t jwe_str_enc(const char *enc);

/**
 * @}
 * @noop jwt_alg_grp
 */

/**
 * @}
 * @noop jwt_grp
 */

/**
 * @defgroup jwe_grp JSON Web Encryption
 *
 * @brief Create and consume JSON Web Encryption (JWE) tokens
 *
 * JWE support is built around two objects that parallel the JWS
 * @ref jwt_builder_t / @ref jwt_checker_t pair but are intentionally
 * distinct types: a JWE is structurally and cryptographically different from
 * a JWS, and keeping the types separate prevents accidentally treating one as
 * the other.
 *
 * Unlike JWS, JWE requires two algorithms: a key management algorithm
 * (@ref jwe_key_alg_t, the ``"alg"`` header) that produces or recovers the
 * Content Encryption Key (CEK), and a content encryption algorithm
 * (@ref jwe_enc_t, the ``"enc"`` header) that authenticates and encrypts the
 * payload with that CEK.
 *
 * Both the Compact Serialization and the JSON Serialization are supported
 * (@ref jwe_serialization_t). The General JSON Serialization carries one or
 * more recipients (@ref jwe_builder_add_recipient): the plaintext is encrypted
 * once with a single CEK and each recipient wraps that CEK independently, so
 * any recipient's key can decrypt the token.
 *
 * @rfc{7516}
 * @{
 */

/**
 * @defgroup jwe_builder_grp Builder
 *
 * @brief Create and encrypt JWE tokens
 *
 * Creating a JWE token mirrors the JWS builder: create a jwe_builder_t,
 * configure it with a recipient key plus a key management (``"alg"``) and
 * content encryption (``"enc"``) algorithm, then generate encrypted tokens.
 * @{
 */

/**
 * @brief Opaque JWE Builder (encryption) object
 * @since 3.4.0
 */
typedef struct jwe_builder jwe_builder_t;

/**
 * @brief Opaque JWE recipient handle
 *
 * Returned by @ref jwe_builder_add_recipient to address one recipient of a
 * General JSON Serialization. The handle is borrowed: it is owned by the
 * builder and valid until the builder is freed; do not free it directly.
 *
 * @rfc{7516,7.2.1}
 * @since 3.4.0
 */
typedef struct jwe_recipient jwe_recipient_t;

/**
 * @brief Create a new JWE builder instance
 *
 * @return Pointer to a JWE builder object on success, NULL on failure
 * @since 3.4.0
 */
JWT_EXPORT
jwe_builder_t *jwe_builder_new(void);

/**
 * @brief Free a previously created JWE builder object
 *
 * @param builder Pointer to a JWE builder object
 * @since 3.4.0
 */
JWT_EXPORT
void jwe_builder_free(jwe_builder_t *builder);

#if defined(__GNUC__) || defined(__clang__) || defined(_DOXYGEN)
/**
 * @brief Helper to free a JWE builder and set the pointer to NULL
 * @param builder Pointer to a pointer for a jwe_builder_t object
 * @since 3.4.0
 */
static inline void jwe_builder_freep(jwe_builder_t **builder) {
	if (builder) {
		jwe_builder_free(*builder);
		*builder = NULL;
	}
}
/**
 * @brief A jwe_builder_t pointer that is freed automatically at scope exit
 *
 * Declares a jwe_builder_t pointer carrying the GCC/Clang ``cleanup``
 * attribute so jwe_builder_free() is invoked on it automatically when the
 * variable goes out of scope. Initialize it where you declare it.
 *
 * @since 3.4.0
 */
#define jwe_builder_auto_t jwe_builder_t \
	__attribute__((cleanup(jwe_builder_freep)))
#endif

/**
 * @brief Check error state of a JWE builder object
 * @param builder Pointer to a JWE builder object
 * @return 0 if no errors exist, non-zero otherwise
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_error(const jwe_builder_t *builder);

/**
 * @brief Get the error message contained in a JWE builder object
 * @param builder Pointer to a JWE builder object
 * @return Pointer to the error message string (empty if none). Never NULL.
 * @since 3.4.0
 */
JWT_EXPORT
const char *jwe_builder_error_msg(const jwe_builder_t *builder);

/**
 * @brief Clear error state in a JWE builder object
 * @param builder Pointer to a JWE builder object
 * @since 3.4.0
 */
JWT_EXPORT
void jwe_builder_error_clear(jwe_builder_t *builder);

/**
 * @brief Set the key and algorithms for a JWE builder
 *
 * @param builder Pointer to a JWE builder object
 * @param alg The JWE key management algorithm (``"alg"`` header)
 * @param enc The JWE content encryption algorithm (``"enc"`` header)
 * @param key The recipient key (a JWK) used for key management
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_setkey(jwe_builder_t *builder, jwe_key_alg_t alg,
		       jwe_enc_t enc, const jwk_item_t *key);

/**
 * @brief Set the ECDH-ES PartyUInfo / PartyVInfo
 *
 * For ECDH-ES key agreement (@ref JWE_ALG_ECDH_ES and the ``+A*KW``
 * variants), these optional octet strings are bound into the Concat KDF and
 * emitted as the ``"apu"`` and ``"apv"`` header parameters. They have no
 * effect for non-ECDH-ES algorithms. Pass NULL (with length 0) to leave one
 * unset. Calling this again replaces any previous values.
 *
 * @param builder Pointer to a JWE builder object
 * @param apu PartyUInfo octets, or NULL
 * @param apu_len Length of @p apu in bytes
 * @param apv PartyVInfo octets, or NULL
 * @param apv_len Length of @p apv in bytes
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_set_partyinfo(jwe_builder_t *builder,
			      const unsigned char *apu, size_t apu_len,
			      const unsigned char *apv, size_t apv_len);

/**
 * @brief Add a recipient to a General JSON Serialization JWE
 *
 * The plaintext is encrypted once with a single CEK; each recipient wraps or
 * encrypts that same CEK independently with its own key management algorithm
 * and key. The first recipient may equivalently be configured with
 * @ref jwe_builder_setkey; this call appends further ones. Adding more than one
 * recipient forces @ref JWE_FORMAT_JSON_GENERAL.
 *
 * The shared content encryption algorithm (``"enc"``) must be set via
 * @ref jwe_builder_setkey. ``dir`` and ECDH-ES Direct (@ref JWE_ALG_ECDH_ES)
 * dictate the CEK from the key, so they cannot be combined with any other
 * recipient.
 *
 * @param builder Pointer to a JWE builder object
 * @param alg The recipient's key management algorithm (``"alg"`` header)
 * @param key The recipient's key (a JWK)
 * @return A borrowed recipient handle (owned by the builder, valid until it is
 *  freed) on success, or NULL on error (with the error set in the builder)
 *
 * @rfc{7516,7.2.1}
 * @since 3.4.0
 */
JWT_EXPORT
jwe_recipient_t *jwe_builder_add_recipient(jwe_builder_t *builder,
					   jwe_key_alg_t alg,
					   const jwk_item_t *key);

/**
 * @brief Set the ECDH-ES PartyUInfo / PartyVInfo for one recipient
 *
 * The per-recipient equivalent of @ref jwe_builder_set_partyinfo, addressing
 * the recipient identified by @p recipient. Has no effect for non-ECDH-ES
 * algorithms. Pass NULL (with length 0) to leave one unset.
 *
 * @param recipient A recipient handle from @ref jwe_builder_add_recipient
 * @param apu PartyUInfo octets, or NULL
 * @param apu_len Length of @p apu in bytes
 * @param apv PartyVInfo octets, or NULL
 * @param apv_len Length of @p apv in bytes
 * @return 0 on success, non-zero otherwise
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_recipient_set_partyinfo(jwe_recipient_t *recipient,
				const unsigned char *apu, size_t apu_len,
				const unsigned char *apv, size_t apv_len);

/**
 * @brief Add a parameter to one recipient's unprotected header
 *
 * Adds an application-defined member to the per-recipient (unprotected) header
 * emitted for @p recipient. @p value_json is parsed as JSON (see
 * @ref jwe_builder_add_protected_json). The library-managed names
 * (``alg``/``enc``/``epk``/``apu``/``apv``) and a duplicate name are rejected;
 * the same name must not also appear in the protected or shared unprotected
 * header (@rfc{7516,7.2.1}).
 *
 * @param recipient A recipient handle from @ref jwe_builder_add_recipient
 * @param key The header parameter name
 * @param value_json The parameter value as a JSON fragment
 * @return 0 on success, non-zero otherwise
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_recipient_add_header_json(jwe_recipient_t *recipient, const char *key,
				  const char *value_json);

/**
 * @brief Select the serialization @ref jwe_builder_generate produces
 *
 * The default is @ref JWE_FORMAT_COMPACT (the five-part string). Selecting
 * @ref JWE_FORMAT_JSON_FLAT or @ref JWE_FORMAT_JSON_GENERAL produces the
 * Flattened or General JSON Serialization respectively. The JSON
 * serializations are required to carry a shared unprotected header
 * (@ref jwe_builder_add_unprotected_json), a per-recipient header, or a JWE
 * AAD member (@ref jwe_builder_set_aad); the Compact Serialization supports
 * none of these.
 *
 * @param builder Pointer to a JWE builder object
 * @param format The serialization to emit
 * @return 0 on success, non-zero otherwise with error set in the builder
 *
 * @rfc{7516,7}
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_set_format(jwe_builder_t *builder, jwe_serialization_t format);

/**
 * @brief Add a parameter to the JWE Protected Header
 *
 * Adds an application-defined member to the integrity-protected JWE header
 * (the ``protected`` member of the JSON serializations, and part of the AAD).
 * The library sets ``"enc"`` (and, for the Compact Serialization, ``"alg"``
 * and the ECDH-ES parameters) itself; those reserved names are rejected here.
 *
 * @p value_json is parsed as JSON, so a string value must include its quotes
 * (the four-byte fragment quote-p-r-o-d-quote for the string @c prod); objects,
 * arrays, numbers and booleans are accepted as written. The same parameter name
 * must not also appear in the shared unprotected or any per-recipient header
 * (@rfc{7516,7.2.1}).
 *
 * @param builder Pointer to a JWE builder object
 * @param key The header parameter name
 * @param value_json The parameter value as a JSON fragment
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_add_protected_json(jwe_builder_t *builder, const char *key,
				   const char *value_json);

/**
 * @brief Add a parameter to the shared JWE Unprotected Header
 *
 * Adds an application-defined member to the shared (not integrity-protected)
 * JWE header, emitted as the ``unprotected`` member of the JSON
 * serializations. Only the JSON serializations can carry it. @p value_json is
 * parsed as JSON (see @ref jwe_builder_add_protected_json). The same parameter
 * name must not also appear in the protected or any per-recipient header.
 *
 * @param builder Pointer to a JWE builder object
 * @param key The header parameter name
 * @param value_json The parameter value as a JSON fragment
 * @return 0 on success, non-zero otherwise with error set in the builder
 *
 * @rfc{7516,7.2.1}
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_add_unprotected_json(jwe_builder_t *builder, const char *key,
				     const char *value_json);

/**
 * @brief Set the JWE Additional Authenticated Data
 *
 * Sets the optional application AAD emitted as the ``aad`` member of the JSON
 * serializations. It is authenticated (bound into the AEAD tag) but not
 * encrypted. Per @rfc{7516,5.1} the AEAD AAD becomes
 * ``ASCII(BASE64URL(protected)) || '.' || BASE64URL(aad)``. Only the JSON
 * serializations can carry it. Pass NULL (with length 0) to clear it.
 *
 * @param builder Pointer to a JWE builder object
 * @param aad The AAD octets, or NULL
 * @param aad_len Length of @p aad in bytes
 * @return 0 on success, non-zero otherwise with error set in the builder
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_builder_set_aad(jwe_builder_t *builder, const unsigned char *aad,
			size_t aad_len);

/**
 * @brief Set the PBES2 iteration count
 *
 * Sets the PBKDF2 iteration count (the ``p2c`` header parameter) used by the
 * ``PBES2-*`` password-based key-management algorithms. Pass 0 to use the
 * library default. A higher count increases resistance to password guessing at
 * the cost of more work per encrypt/decrypt; it has no effect on non-PBES2
 * algorithms. On decrypt the library enforces a hard maximum on an
 * attacker-supplied ``p2c`` regardless of this setting.
 *
 * @param builder Pointer to a JWE builder object
 * @param p2c The PBKDF2 iteration count, or 0 for the library default
 * @return 0 on success, non-zero otherwise
 * @since 3.6.0
 */
JWT_EXPORT
int jwe_builder_setpbes2(jwe_builder_t *builder, unsigned int p2c);

/**
 * @brief Encrypt a plaintext into a JWE
 *
 * Produces a JWE using the key and algorithms configured with
 * @ref jwe_builder_setkey. The serialization is the Compact Serialization (a
 * five-part string) unless changed with @ref jwe_builder_set_format.
 *
 * @param builder Pointer to a JWE builder object
 * @param plaintext The bytes to encrypt
 * @param plaintext_len Length of @p plaintext in bytes
 * @return A newly allocated, nil-terminated JWE string the caller must free,
 *  or NULL on error (with the error set in the builder)
 * @since 3.4.0
 */
JWT_EXPORT
char *jwe_builder_generate(jwe_builder_t *builder,
			   const unsigned char *plaintext,
			   size_t plaintext_len);

/**
 * @}
 * @noop jwe_builder_grp
 */

/**
 * @defgroup jwe_checker_grp Checker
 *
 * @brief Decrypt and authenticate JWE tokens
 *
 * Consuming a JWE token mirrors the JWS checker: create a jwe_checker_t,
 * configure it with the key and the expected algorithms, then decrypt and
 * authenticate tokens.
 * @{
 */

/**
 * @brief Opaque JWE Checker (decryption) object
 * @since 3.4.0
 */
typedef struct jwe_checker jwe_checker_t;

/**
 * @brief Create a new JWE checker instance
 *
 * @return Pointer to a JWE checker object on success, NULL on failure
 * @since 3.4.0
 */
JWT_EXPORT
jwe_checker_t *jwe_checker_new(void);

/**
 * @brief Free a previously created JWE checker object
 *
 * @param checker Pointer to a JWE checker object
 * @since 3.4.0
 */
JWT_EXPORT
void jwe_checker_free(jwe_checker_t *checker);

#if defined(__GNUC__) || defined(__clang__) || defined(_DOXYGEN)
/**
 * @brief Helper to free a JWE checker and set the pointer to NULL
 * @param checker Pointer to a pointer for a jwe_checker_t object
 * @since 3.4.0
 */
static inline void jwe_checker_freep(jwe_checker_t **checker) {
	if (checker) {
		jwe_checker_free(*checker);
		*checker = NULL;
	}
}
/**
 * @brief A jwe_checker_t pointer that is freed automatically at scope exit
 *
 * Declares a jwe_checker_t pointer carrying the GCC/Clang ``cleanup``
 * attribute so jwe_checker_free() is invoked on it automatically when the
 * variable goes out of scope. Initialize it where you declare it.
 *
 * @since 3.4.0
 */
#define jwe_checker_auto_t jwe_checker_t \
	__attribute__((cleanup(jwe_checker_freep)))
#endif

/**
 * @brief Check error state of a JWE checker object
 * @param checker Pointer to a JWE checker object
 * @return 0 if no errors exist, non-zero otherwise
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_checker_error(const jwe_checker_t *checker);

/**
 * @brief Get the error message contained in a JWE checker object
 * @param checker Pointer to a JWE checker object
 * @return Pointer to the error message string (empty if none). Never NULL.
 * @since 3.4.0
 */
JWT_EXPORT
const char *jwe_checker_error_msg(const jwe_checker_t *checker);

/**
 * @brief Clear error state in a JWE checker object
 * @param checker Pointer to a JWE checker object
 * @since 3.4.0
 */
JWT_EXPORT
void jwe_checker_error_clear(jwe_checker_t *checker);

/**
 * @brief Set the key and algorithms for a JWE checker
 *
 * @param checker Pointer to a JWE checker object
 * @param alg The expected JWE key management algorithm (``"alg"`` header)
 * @param enc The expected JWE content encryption algorithm (``"enc"`` header)
 * @param key The key (a JWK) used to recover the CEK
 * @return 0 on success, non-zero otherwise with error set in the checker
 * @since 3.4.0
 */
JWT_EXPORT
int jwe_checker_setkey(jwe_checker_t *checker, jwe_key_alg_t alg,
		       jwe_enc_t enc, const jwk_item_t *key);

/**
 * @brief Decrypt and authenticate a Compact Serialization JWE
 *
 * Parses the five-part token, recovers the CEK using the configured key and
 * algorithms (@ref jwe_checker_setkey), and verifies the authentication tag.
 *
 * @param checker Pointer to a JWE checker object
 * @param token A nil-terminated compact JWE string
 * @param plaintext_len If non-NULL, set to the length of the returned
 *  plaintext on success
 * @return A newly allocated buffer of decrypted plaintext the caller must
 *  free, or NULL on error (with the error set in the checker). The buffer is
 *  nil-terminated for convenience, but @p plaintext_len gives the true length.
 * @since 3.4.0
 */
JWT_EXPORT
unsigned char *jwe_checker_decrypt(jwe_checker_t *checker, const char *token,
				   size_t *plaintext_len);

/**
 * @brief Decrypt and authenticate a JWE in any serialization
 *
 * Like @ref jwe_checker_decrypt, but auto-detects the serialization: a token
 * beginning with ``{`` is parsed as a JSON Serialization (Flattened or
 * General), otherwise as the Compact Serialization. For a General JWE the
 * checker selects the recipient matching its configured key and algorithm.
 *
 * @param checker Pointer to a JWE checker object
 * @param token A nil-terminated JWE string (compact or JSON)
 * @param plaintext_len If non-NULL, set to the length of the returned
 *  plaintext on success
 * @return A newly allocated, nil-terminated buffer of decrypted plaintext the
 *  caller must free, or NULL on error (with the error set in the checker)
 *
 * @rfc{7516,7}
 * @since 3.4.0
 */
JWT_EXPORT
unsigned char *jwe_checker_decrypt_all(jwe_checker_t *checker,
				       const char *token, size_t *plaintext_len);

/**
 * @brief Get the JWE AAD recovered from a JSON-serialized token
 *
 * After a successful @ref jwe_checker_decrypt_all on a JSON Serialization that
 * carried an ``aad`` member, returns the authenticated application AAD octets.
 * Returns NULL if the last token had no AAD member (or was compact). The
 * returned buffer is owned by the checker and valid until the next decrypt or
 * until the checker is freed.
 *
 * @param checker Pointer to a JWE checker object
 * @param aad_len If non-NULL, set to the length of the returned AAD in bytes
 * @return Pointer to the AAD octets, or NULL if none
 * @since 3.4.0
 */
JWT_EXPORT
const unsigned char *jwe_checker_get_aad(const jwe_checker_t *checker,
					 size_t *aad_len);

/**
 * @}
 * @noop jwe_checker_grp
 */

/**
 * @}
 * @noop jwe_grp
 */

/**
 * @defgroup jwks_grp JSON Web Keys
 *
 * @brief Load and use JSON Web Keys (JWK) and Key Sets (JWKS)
 * @{
 */

/**
 * @defgroup jwks_core_grp JWK Management
 *
 * @brief Create and manage keyrings of JWK and JWKS keys
 *
 * Functions to handle JSON that represents JWK and JWKS for use in validating
 * or signing JWT objects.
 *
 * @note The jwks_create functions are convenience wrappers around the same-named
 *  jwks_load functions. They explicitly create a keyring.
 *
 * @note If you want to create an empty keyring, simply call jwks_create(NULL)
 *
 * @{
 */

/**
 * @brief Create or add to a keyring from a null terminated string
 *
 * This function, and the utility versions, allow you to create a keyring
 * used to verify and/or create JSON Web Tokens. It accepts either single
 * JWK or a JWKS (JSON Web Token Set).
 *
 * If you want to create a new set, then pass NULL as the first argument. If
 * you want to add to an existing keyring, then pass that as the first
 * argument.
 *
 * If non-NULL is returned, you should then check to make sure there
 * is no error with jwks_error(). There may be errors on individual
 * JWK items in the set. You can check if there are any with
 * jwks_error_any().
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwt_set
 *   to add new keys to it.
 * @param jwk_json_str JSON string representation of a single key
 *   or array of "keys".
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_load(jwk_set_t *jwk_set, const char *jwk_json_str);

/**
 * @brief Create or add to a keyring from a string of known length
 *
 * Useful if the string is not null terminated. Otherwise, it works the same
 * as jwks_load().
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwt_set
 *   to add new keys to it.
 * @param jwk_json_str JSON string representation of a single key
 *   or array of "keys".
 * @param len The length of jwk_json_str that represents the key(s) being
 *   read.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_strn(jwk_set_t *jwk_set, const char *jwk_json_str,
			    const size_t len);

/**
 * @brief Create or add to a keyring from a file
 *
 * The JSON will be read from a file on the system. Must be readable by the
 * running process. The end result of this function is the same as jwks_load.
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwt_set
 *   to add new keys to it.
 * @param file_name A file containing a JSON representation of a single key
 *   or array of "keys".
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromfile(jwk_set_t *jwk_set, const char *file_name);

/**
 * @brief Create or add to a keyring from a FILE pointer
 *
 * The JSON will be read from a FILE pointer. The end result of this function
 * is the same as jwks_load. The FILE pointer must be set to the starting
 * position of the JWK data. This function will read until it reaches EOF or
 * invalid JSON data.
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwt_set
 *   to add new keys to it.
 * @param input A FILE pointer where the JSON representation of a single key
 *   or array of "keys" can be fread() from.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromfp(jwk_set_t *jwk_set, FILE *input);

/**
 * @brief Create or add to a keyring from a URL
 *
 * The JSON will be retrieved from a URL. This can be any URL understood by
 * by Libcurl.
 *
 * Example: https://example.com/.well-known/jwks.json
 *
 * @warning You should not have private keys available on public web sites.
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwt_set
 *   to add new keys to it.
 * @param url A string URL to where the JSON representation of a single key
 *   or array of "keys" can be retrieved from. Generally a json file.
 * @param verify Set to non-zero to fully verify the TLS connection
 *   (certificate chain/peer @b and hostname); set to 0 to disable
 *   verification entirely. Non-zero is strongly recommended: hostname
 *   verification on its own is meaningless, so any value >= 1 enables
 *   both peer and host verification. 0 disables all verification and is
 *   insecure (use only for testing).
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 * @since 3.2.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromurl(jwk_set_t *jwk_set, const char *url, int verify);

/**
 * @brief Wrapper around jwks_load() that explicitly creates a new keyring
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_create(const char *jwk_json_str);

/**
 * @brief Wrapper around jwks_load_strn() that explicitly creates a new keyring
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_strn(const char *jwk_json_str, const size_t len);

/**
 * @brief Wrapper around jwks_load_fromfile() that explicitly creates a new
 *  keyring
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromfile(const char *file_name);

/**
 * @brief Wrapper around jwks_load_fromfp() that explicitly creates a new
 *  keyring
 * @since 3.0.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromfp(FILE *input);

/**
 * @brief Wrapper around jwks_load_fromurl() that explicitly creates a new
 *  keyring
 * @since 3.2.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromurl(const char *url, int verify);

/**
 * @brief Flags controlling how a native key is imported into a keyring
 *
 * Used with the jwks_load_fromkey() and jwks_create_fromkey() family. The
 * input to those functions may be a PEM file, a DER file, or (with
 * ::JWK_KEY_TRY_HMAC) raw bytes treated as an HMAC key, so these flags are
 * named JWK_KEY_* rather than anything PEM-specific.
 * @since 3.4.0
 */
typedef enum {
	JWK_KEY_NONE		= 0x0000,	/**< No options */
	JWK_KEY_GEN_KID		= 0x0001,	/**< Generate a deterministic
						     "kid" (the @rfc{7638} JWK
						     SHA-256 thumbprint) for each
						     imported key */
	JWK_KEY_TRY_HMAC	= 0x0002,	/**< If the input does not parse
						     as a PEM/DER key, treat the
						     raw bytes as an "oct" (HMAC)
						     key */
} jwk_key_flags_t;

/**
 * @brief Create or add to a keyring by importing a native key
 *
 * Import a key that is NOT already in JWK form — a PEM or DER encoded public
 * or private key (RSA, RSA-PSS, EC, or EdDSA), or (with ::JWK_KEY_TRY_HMAC)
 * raw bytes treated as an HMAC key — and convert it into a JWK in the keyring.
 * This is the inverse of jwks_item_pem().
 *
 * As with jwks_load(), pass NULL as @p jwk_set to create a new keyring, or an
 * existing one to add to it. On success you should check jwks_error() and
 * jwks_error_any() as with any other loader.
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwk_set_t to
 *   add the imported key to.
 * @param key A buffer holding a single PEM, DER, or raw key.
 * @param len The length of @p key in bytes.
 * @param flags A bitwise OR of ::jwk_key_flags_t values (or ::JWK_KEY_NONE).
 * @return A valid jwk_set_t on success. On failure, either NULL or a
 *   jwk_set_t with error set. NULL generally means ENOMEM or that the key
 *   could not be parsed.
 * @since 3.4.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromkey(jwk_set_t *jwk_set, const char *key,
			     const size_t len, unsigned int flags);

/**
 * @brief Create or add to a keyring by importing a native key from a file
 *
 * Like jwks_load_fromkey(), but reads the key from a file (PEM or DER).
 *
 * @param jwk_set Either NULL to create a new set, or an existing jwk_set_t to
 *   add the imported key to.
 * @param file_name Path to a file holding a single PEM, DER, or raw key.
 * @param flags A bitwise OR of ::jwk_key_flags_t values (or ::JWK_KEY_NONE).
 * @return A valid jwk_set_t on success. On failure, either NULL or a
 *   jwk_set_t with error set.
 * @since 3.4.0
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromkey_file(jwk_set_t *jwk_set, const char *file_name,
				  unsigned int flags);

/**
 * @brief Wrapper around jwks_load_fromkey() that explicitly creates a new
 *  keyring
 * @since 3.4.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromkey(const char *key, const size_t len,
			       unsigned int flags);

/**
 * @brief Wrapper around jwks_load_fromkey_file() that explicitly creates a new
 *  keyring
 * @since 3.4.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromkey_file(const char *file_name, unsigned int flags);

/**
 * @brief Generate a new key and add it to a keyring as a JWK
 *
 * Generates a fresh key of type @p kty and appends it to @p jwk_set as a new
 * ::jwk_item_t (a private JWK), returning the set. Pass NULL for @p jwk_set to
 * create a new keyring. The generated key is bound to the active crypto backend,
 * so it can be used directly for signing/verifying or JWE.
 *
 * @p param selects the key geometry, interpreted by @p kty (NULL or "" picks a
 * sensible default):
 *  - EC: the curve — ``"P-256"`` (default), ``"P-384"``, ``"P-521"``, ``"secp256k1"``
 *  - OKP: the curve — ``"Ed25519"`` (default), ``"Ed448"``, ``"X25519"``, ``"X448"``
 *  - RSA: the modulus size in bits — ``"2048"`` (default), ``"3072"``, ``"4096"``
 *  - oct: the key size in bits — ``"256"`` (default), ``"384"``, ``"512"``
 *  - AKP (ML-DSA): ignored (the variant comes from @p alg)
 *
 * @p alg is the JWA discriminator. It is optional for EC/OKP/oct (it stamps the
 * JWK ``"alg"``), distinguishes RSA (``RS*``) from RSA-PSS (``PS*``) for
 * ``kty=RSA``, and is REQUIRED for AKP to pin the ML-DSA variant
 * (``JWT_ALG_ML_DSA_44/65/87``). Pass ::JWT_ALG_NONE for none. It must be
 * compatible with @p kty.
 *
 * @p flags is a bitwise OR of ::jwk_key_flags_t; ::JWK_KEY_GEN_KID stamps the
 * RFC 7638 thumbprint as the ``"kid"``.
 *
 * A backend that cannot generate the requested key (e.g. MbedTLS has no EdDSA)
 * does not crash: the appended item carries an error (jwks_item_error()).
 *
 * @param jwk_set A keyring to append to, or NULL to create a new one
 * @param kty The key type to generate
 * @param param The key geometry selector (see above), or NULL for the default
 * @param alg The JWA algorithm discriminator, or ::JWT_ALG_NONE
 * @param flags A bitwise OR of ::jwk_key_flags_t values (or ::JWK_KEY_NONE)
 * @return The keyring with the new key appended, or NULL on allocation failure
 * @since 3.6.0
 */
JWT_EXPORT
jwk_set_t *jwks_generate(jwk_set_t *jwk_set, jwk_key_type_t kty,
			 const char *param, jwt_alg_t alg, unsigned int flags);

/**
 * @brief Wrapper around jwks_generate() that explicitly creates a new keyring
 * @since 3.6.0
 */
JWT_EXPORT
jwk_set_t *jwks_create_generate(jwk_key_type_t kty, const char *param,
				jwt_alg_t alg, unsigned int flags);

/**
 * @brief Check if there is an error with a jwk_set
 *
 * An Error in a jwk_set is usually passive and generally means there was an
 * issue loading the JWK(S) data.
 *
 * To get a string describing the error, use jwks_error_msg(). You can clear
 * the error with jwks_error_clear().
 *
 * @param jwk_set An existing jwk_set_t
 * @return 0 if no error exists, 1 if it does exists.
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_error(const jwk_set_t *jwk_set);

/**
 * @brief Check if there is an error within the jwk_set and any of
 * the jwk_item_t in the set.
 *
 * @param jwk_set An existing jwk_set_t
 * @return 0 if no error exists, or the number of errors in the set
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_error_any(const jwk_set_t *jwk_set);

/**
 * @brief Retrieve an error message from a jwk_set
 *
 * @note A zero length string is valid even if jwks_error() returns non-zero.
 *
 * @param jwk_set An existing jwk_set_t
 * @return A string message. The string may be empty.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwks_error_msg(const jwk_set_t *jwk_set);

/**
 * @brief Clear an error condition in a jwk_set
 *
 * @param jwk_set An existing jwk_set_t
 * @since 3.0.0
 */
JWT_EXPORT
void jwks_error_clear(jwk_set_t *jwk_set);

/**
 * Free all memory associated with a jwt_set_t, including any jwk_item_t in
 * the set.
 *
 * @param jwk_set An existing jwk_set_t
 * @since 3.0.0
 */
JWT_EXPORT
void jwks_free(jwk_set_t *jwk_set);

#if defined(__GNUC__) || defined(__clang__) || defined(_DOXYGEN)
/**
 * @brief Helper function to free a JWK Set and set the pointer to NULL
 *
 * This is mainly to use with the jwk_set_auto_t type.
 *
 * @param Pointer to a pointer for a jwk_set_t object
 * @since 3.0.0
 */
static inline void jwks_freep(jwk_set_t **jwks) {
	if (jwks) {
		jwks_free(*jwks);
		*jwks = NULL;
	}
}
/**
 * @brief A jwk_set_t pointer that is freed automatically at scope exit
 *
 * Declares a jwk_set_t pointer carrying the GCC/Clang ``cleanup`` attribute
 * so jwks_free() is invoked on it automatically when the variable goes out
 * of scope. Initialize it where you declare it.
 *
 * @since 3.0.0
 */
#define jwk_set_auto_t jwk_set_t __attribute__((cleanup(jwks_freep)))
#endif

/**
 * @}
 * @noop jwks_core_grp
 */

/**
 * @defgroup jwks_item_grp JSON Web Key Usage
 *
 * @brief Inspect and use individual JWK items from a keyring
 *
 * Functionality for using a JWK (represented as a jwk_item_t) to sign and
 * validate JWT objects.
 *
 * @{
 */

/**
 * @brief Return the index'th jwk_item in the jwk_set
 *
 * Allows you to obtain the raw jwk_item. NOTE, this is not a copy of the item,
 * which means if the jwk_set is freed, then this data is freed and cannot be
 * used.
 *
 * @param jwk_set An existing jwk_set_t
 * @param index Index of the jwk_set
 * @return A valid jwk_item_t or NULL if it doesn't exist
 *
 * @warning The index of an item in a keyring can change if items are deleted.
 *  Effort is made to add new JWK to the end of the set, so this should not
 *  affect the index of previous items.
 * @since 3.0.0
 */
JWT_EXPORT
const jwk_item_t *jwks_item_get(const jwk_set_t *jwk_set, size_t index);

/**
 * @brief Find a jwk_item_t with a specific kid (Key ID)
 *
 * LibJWT does not ensure that kid's are unique in a given keyring, so care
 * must be taken. This will return the first match.
 *
 * @param jwk_set An existing jwk_set_t
 * @param kid String representing a ``kid`` to find
 * @return A jwk_item_t object or NULL if none found
 * @since 3.2.0
 */
JWT_EXPORT
jwk_item_t *jwks_find_bykid(jwk_set_t *jwk_set, const char *kid);

/**
 * @brief Whether this key is private (or public)
 *
 * @param item A JWK Item
 * @return 1 for true, 0 for false
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_is_private(const jwk_item_t *item);

/**
 * @brief Check the error condition for this JWK
 *
 * @param item A JWK Item
 * @return 1 for true, 0 for false
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_error(const jwk_item_t *item);

/**
 * @brief Check the error message for a JWK Item
 *
 * @param item A JWK Item
 * @return A string message. Empty string if no error.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwks_item_error_msg(const jwk_item_t *item);

/**
 * @brief A curve name, if applicable, for this key
 *
 * Mainly applies to EC and OKP (EdDSA) type keys.
 *
 * @param item A JWK Item
 * @return A string of the curve name if one exists. NULL otherwise.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwks_item_curve(const jwk_item_t *item);

/**
 * @brief A kid (Key ID) for this JWK
 *
 * @param item A JWK Item
 * @return A string of the kid if one exists. NULL otherwise.
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwks_item_kid(const jwk_item_t *item);

/**
 * @brief The algorithm for this JWK
 *
 * It is perfectly valid for this to be JWT_ALG_NONE.
 *
 * @param item A JWK Item
 * @return A jwt_alg_t type of this key
 * @since 3.0.0
 */
JWT_EXPORT
jwt_alg_t jwks_item_alg(const jwk_item_t *item);

/**
 * @brief The Key Type of this JWK
 *
 * @param item A JWK Item
 * @return A jwk_key_type_t type for this key
 * @since 3.0.0
 */
JWT_EXPORT
jwk_key_type_t jwks_item_kty(const jwk_item_t *item);

/**
 * @brief The ``"use"`` field for this JWK
 *
 * @param item A JWK Item
 * @return A jwk_pub_key_use_t type for this key
 * @since 3.0.0
 */
JWT_EXPORT
jwk_pub_key_use_t jwks_item_use(const jwk_item_t *item);

/**
 * @brief The ``"key_ops"`` field for this JWK
 *
 * @param item A JWK Item
 * @return A jwk_key_op_t type for this key which represents all of the
 *   ``"key_ops"`` supported as a bit field.
 * @since 3.0.0
 */
JWT_EXPORT
jwk_key_op_t jwks_item_key_ops(const jwk_item_t *item);

/**
 * @brief The PEM generated for the JWK
 *
 * This is an optional field that may or may not be supported depending on
 * which crypto backend is in use. It is provided as a courtesy.
 *
 * @param item A JWK Item
 * @return A string of the PEM file for this key or NULL if none exists
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwks_item_pem(const jwk_item_t *item);

/**
 * @brief Serialize a single JWK item to a JWK JSON string
 *
 * Produces the JSON Web Key representation of this item. This is the
 * serialization counterpart to the jwks_load_fromkey() import path.
 *
 * @param item A JWK Item
 * @param priv If non-zero, include private key parameters when the item is a
 *   private key. If zero, only public parameters are emitted.
 * @return A newly allocated, nil-terminated JSON string the caller must free
 *   with free(), or NULL on error.
 * @since 3.4.0
 */
JWT_EXPORT
char *jwks_item_export(const jwk_item_t *item, int priv);

/**
 * @brief Serialize a whole keyring to a JWKS JSON string
 *
 * Produces a JWK Set (an object with a @c "keys" array) containing every item
 * in the set.
 *
 * @param jwk_set An existing jwk_set_t
 * @param priv If non-zero, include private key parameters for private keys. If
 *   zero, only public parameters are emitted.
 * @return A newly allocated, nil-terminated JSON string the caller must free
 *   with free(), or NULL on error.
 * @since 3.4.0
 */
JWT_EXPORT
char *jwks_export(const jwk_set_t *jwk_set, int priv);

/**
 * @brief Hash algorithm for a JWK Thumbprint
 *
 * Selects the digest used by jwks_item_thumbprint() and
 * jwks_item_thumbprint_uri(). SHA-256 is the value 0, so it is the default for
 * a zero-initialized argument and is what virtually all deployments use.
 *
 * @since 3.6.0
 */
typedef enum {
	JWK_THUMBPRINT_SHA256 = 0,	/**< SHA-256 (default) */
	JWK_THUMBPRINT_SHA384,		/**< SHA-384 */
	JWK_THUMBPRINT_SHA512,		/**< SHA-512 */
} jwk_thumbprint_alg_t;

/**
 * @brief Compute the JWK Thumbprint of a key
 *
 * @rfc{7638,3}
 *
 * Produces the base64url-encoded SHA-2 digest of the key's canonical JWK form:
 * a JSON object containing only the members required for the key type, with no
 * whitespace and the member names in lexicographic order. The result is a
 * stable, deterministic fingerprint of the (public) key parameters, commonly
 * used as a key id (@c "kid") or as the @c "jkt" confirmation value.
 *
 * The thumbprint is computed over public parameters and is identical whether
 * the item was loaded from a JWK or from a PEM/DER key.
 *
 * @param item A JWK Item
 * @param alg The thumbprint hash algorithm (see @ref jwk_thumbprint_alg_t);
 *   @ref JWK_THUMBPRINT_SHA256 is the default.
 * @return A newly allocated, nil-terminated base64url string the caller must
 *   free with free(), or NULL on error (an unusable key, a missing required
 *   member, or an invalid @p alg).
 * @since 3.6.0
 */
JWT_EXPORT
char *jwks_item_thumbprint(const jwk_item_t *item, jwk_thumbprint_alg_t alg);

/**
 * @brief Compute the JWK Thumbprint URI of a key
 *
 * @rfc{9278}
 *
 * As jwks_item_thumbprint(), but returns the RFC 9278 URI form:
 * @c "urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>" (or
 * @c sha-384 / @c sha-512 to match @p alg).
 *
 * @param item A JWK Item
 * @param alg The thumbprint hash algorithm (see @ref jwk_thumbprint_alg_t);
 *   @ref JWK_THUMBPRINT_SHA256 is the default.
 * @return A newly allocated, nil-terminated URI string the caller must free
 *   with free(), or NULL on error.
 * @since 3.6.0
 */
JWT_EXPORT
char *jwks_item_thumbprint_uri(const jwk_item_t *item, jwk_thumbprint_alg_t alg);

/**
 * @brief Find a key in a set by its JWK Thumbprint
 *
 * @rfc{7638}
 *
 * Returns the first item in @p jwk_set whose thumbprint (for the given hash)
 * equals @p thumbprint. Unlike jwks_find_bykid(), this matches on the key's
 * canonical, deterministic identity rather than the advisory @c "kid", so it
 * works even when keys carry no (or an inconsistent) @c "kid" — e.g. matching a
 * proof-of-possession @c "cnf"/@c "jkt" value against a set of known keys.
 *
 * @param jwk_set An existing jwk_set_t
 * @param alg The hash used to produce @p thumbprint (see @ref jwk_thumbprint_alg_t)
 * @param thumbprint A base64url JWK thumbprint, as from jwks_item_thumbprint()
 * @return The matching jwk_item_t, or NULL if none matches or on bad input
 * @since 3.6.0
 */
JWT_EXPORT
jwk_item_t *jwks_find_bythumbprint(jwk_set_t *jwk_set, jwk_thumbprint_alg_t alg,
				   const char *thumbprint);

/**
 * @brief Find a key in a set by its JWK Thumbprint URI
 *
 * @rfc{9278}
 *
 * As jwks_find_bythumbprint(), but takes the RFC 9278 URI form
 * (@c "urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>"); the hash
 * is taken from the URI's @c sha-NNN label.
 *
 * @param jwk_set An existing jwk_set_t
 * @param uri A JWK Thumbprint URI, as from jwks_item_thumbprint_uri()
 * @return The matching jwk_item_t, or NULL if none matches or on bad input
 * @since 3.6.0
 */
JWT_EXPORT
jwk_item_t *jwks_find_bythumbprint_uri(jwk_set_t *jwk_set, const char *uri);

/**
 * @brief Retrieve binary octet data of a key
 *
 * Only valid for JWT_KEY_TYPE_OCT.
 *
 * @param item A JWK Item
 * @param buf Pointer to a pointer buffer
 * @param len Pointer to a length
 * @return 0 on success. @p buf will point to data of @c len length. Non-zero on
 *  error.
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_key_oct(const jwk_item_t *item, const unsigned char **buf,
		      size_t *len);

/**
 * @brief The number of bits in this JWK
 *
 * This is relevant to the key type (kty). E.g. an RSA key would have at least
 * 2048 bits, and an EC key would be 256, 384, or 521 bits, etc.
 *
 * @param item A JWK Item
 * @return The number of bits for the key
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_key_bits(const jwk_item_t *item);

/**
 * @brief Free remove and free the nth jwk_item_t in a jwk_set
 *
 * @param jwk_set Pointer to a JWKS object
 * @param index the position of the item in the index
 * @return 0 if no item was was deleted (found), 1 if it was
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_free(jwk_set_t *jwk_set, size_t index);

/**
 * @brief Remove and free all jwk_item_t in a jwk_set_t
 *
 * The jwk_set_t becomes an empty set.
 *
 * @param jwk_set Pointer to a JWKS object
 * @return The number of items deleted
 * @since 3.0.0
 */
JWT_EXPORT
int jwks_item_free_all(jwk_set_t *jwk_set);

/**
 * @brief Free all keys marked with an error in a jwk_set_t
 *
 * The jwk_set_t becomes an empty set.
 *
 * @param jwk_set Pointer to a JWKS object
 * @return The number of items with an error that were deleted
 * @since 3.1.0
 */
JWT_EXPORT
int jwks_item_free_bad(jwk_set_t *jwk_set);

/**
 * @brief Return the number of keys in a jwk_set_t
 *
 * @param jwk_set Pointer to a JWKS object
 * @return The number of items in the set
 * @since 3.1.0
 */
JWT_EXPORT
size_t jwks_item_count(const jwk_set_t *jwk_set);

/**
 * @}
 * @noop jwks_item_grp
 */

/**
 * @}
 * @noop jwks_grp
 */

/**
 * @defgroup jwt_advanced_grp Advanced Functionality
 *
 * @brief Configure memory allocators and crypto backends
 * @{
 */

/**
 * @defgroup jwt_memory_grp Memory Handlers
 *
 * @brief Get or set the memory allocation functions LibJWT uses
 *
 * These functions allow you to get or set memory allocation functions.
 * @{
 */

 /**
  * @brief Set functions to be used for memory management
  *
  * By default, LibJWT uses malloc and free for memory
  * management. This function allows the user of the library to
  * specify its own memory management functions. This is especially
  * useful on Windows where mismatches in runtimes across DLLs can
  * cause problems.
  *
  * The caller can specify either a valid function pointer for
  * any of the parameters or NULL to use the corresponding default
  * allocator function.
  *
  * @note This function will also set the memory allocator for the Jansson
  * library.
  *
  * @param pmalloc The function to use for allocating memory or
  *     NULL to use malloc
  * @param pfree The function to use for freeing memory or
  *     NULL to use free
  * @returns 0 on success or errno otherwise.
  * @since 3.0.0
  */
JWT_EXPORT
int jwt_set_alloc(jwt_malloc_t pmalloc, jwt_free_t pfree);

/**
 * Get functions used for allocating and freeing memory.
 *
 * @param pmalloc Pointer to malloc function output variable, or NULL
 * @param pfree Pointer to free function output variable, or NULL
 * @since 3.0.0
 */
JWT_EXPORT
void jwt_get_alloc(jwt_malloc_t *pmalloc, jwt_free_t *pfree);

 /**
  * @}
  * @noop jwt_memory_grp
  */

/**
 * @defgroup jwt_crypto_grp Cryptographic Ops
 *
 * @brief Select which crypto backend LibJWT uses
 *
 * Functions used to set and get which crypto operations are used
 *
 * LibJWT supports several crypto libraries, mainly "openssl", "gnutls",
 * and "mbedtls". By default, "openssl" is used.
 *
 * @warning Changing the crypto operations is not thread safe. You must
 *   protect changing them with some sort of lock, including locking
 *   around usage of the operations themselves. Ideally, you should only
 *   perform this at the start of your application before using any of
 *   LibJWTs functions. Failing to follow this guide can lead to crashes
 *   in certain situations.
 *
 * @remark ENVIRONMENT: You can set JWT_CRYPTO to the default operations you
 * wish to use. If JWT_CRYPTO is invalid, an error message will be
 * printed to the console when LibJWT is loaded by the application.
 * @{
 */

/**
 * Retrieve the name of the current crypto operations being used.
 *
 * @return name of the crypto operation set
 * @since 3.0.0
 */
JWT_EXPORT
const char *jwt_get_crypto_ops(void);

/**
 * Retrieve the type of the current crypto operations being used.
 *
 * @return jwt_crypto_provider_t of the crypto operation set
 * @since 3.0.0
 */
JWT_EXPORT
jwt_crypto_provider_t jwt_get_crypto_ops_t(void);

/**
 * Set the crypto operations to the named set.
 *
 * The opname is one of the available operators in the compiled version
 * of LibJWT. Most times, this is either "openssl" or "gnutls".
 *
 * @note A key (@ref jwk_item_t) remains bound to the backend that parsed it:
 *  signing, verifying, and JWE operations on that key always route to its
 *  origin backend, regardless of the backend selected here. So changing the
 *  active backend after loading keys is safe — each key keeps working. (Keys
 *  with no backend-specific material, i.e. @c "oct", use the active backend.)
 *
 * @param opname the name of the crypto operation to set
 * @return 0 on success, 1 for error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_set_crypto_ops(const char *opname);

/**
 * Set the crypto operations to a jwt_crypto_provider_t type
 *
 * The same as jwt_set_crypto_ops(), but uses the type as opname
 *
 * @param opname A valid jwt_crypto_provider_t type
 * @return 0 on success, 1 for error
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_set_crypto_ops_t(jwt_crypto_provider_t opname);

/**
 * Check if the current crypto operations support JWK usage
 *
 * @return 1 if it does, 0 if not
 * @since 3.0.0
 */
JWT_EXPORT
int jwt_crypto_ops_supports_jwk(void);

/**
 * @}
 * @noop jwt_crypto_grp
 */

/**
 * @}
 * @noop jwt_advanced_grp
 */

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
