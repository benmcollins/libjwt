/* Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
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
 */

#ifndef JWT_H
#define JWT_H

#include <jwt_export.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup jwt_core_grp
 * @brief Opaque JWT object
 *
 * This object is used throughout the JWT functions.
 *
 * @remark When creating a JWT object (encoding), this stores state until
 *  you call one of the encoding functions. When dedcoding a JSON Web Token
 *  this object is returned so you can inspect it further (e.g. retrieve
 *  grants).
 */
typedef struct jwt jwt_t;

/** @ingroup jwt_valid_grp
 * @brief Opaque JWT Validation object
 *
 * Used in the JWT validation functions.
 */
typedef struct jwt_valid jwt_valid_t;

/** @ingroup jwks_core_grp
 * @brief Opaque JWKS object
 *
 * Used for working with JSON Web Keys and JWK Sets (JWKS).
 *
 * @remark All JWK operations require that you import your JWK into a
 *  jwk_set_t first. Internal, LibJWT creates a jwk_set_t even for single
 *  keys. This makes code pretty much the same whether working with one JWK
 *  or a set of them.
 */
typedef struct jwk_set jwk_set_t;

/** @ingroup jwt_core_grp
 * @brief JWT algorithm types
 *
 * These are the supported algorithm types for LibJWT.
 *
 * @warning You should not assume that this directly relates to what may be
 *  in the JWT header. The internal state of the jwt_t object and the JSON
 *  data are only guarateed to be in sync during encoding and decoding.
 *
 * @note For HMAC algorithms, the key can be any data, even binary. However,
 *   for all the other algorithms, the key is expected to be in a format
 *   that the underlying @ref jwt_crypto_grp can interpret. Generally, PEM
 *   is a safe bet.
 *
 * @rfc{7518,3.1}
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
	JWT_ALG_EDDSA,		/**< EdDSA using Ed25519 */
	JWT_ALG_INVAL,		/**< An invalid algorithm from the caller or the token */
} jwt_alg_t;

/** @ingroup jwt_crypto_grp
 * @brief  Different providers for crypto operations
 *
 * Used to set or test the underlying cryptographic library provider.
 *
 * @remark These being present are not a guarantee that the JWT library
 *  has been compiled to support it. Also, certain functions of the
 *  library may not be supported by each. For example, not all of them
 *  support JWKS operations.
 **/
typedef enum {
	JWT_CRYPTO_OPS_NONE = 0,	/**< Used for error handling */
	JWT_CRYPTO_OPS_OPENSSL,		/**< OpenSSL Library */
	JWT_CRYPTO_OPS_GNUTLS,		/**< GnuTLS Library */
	JWT_CRYPTO_OPS_MBEDTLS,		/**< MBedTLS embedded library */
} jwt_crypto_provider_t;

/** @ingroup jwks_core_grp
 * @brief JWK Key Types
 *
 * Corresponds to the ``"kty"`` attribute of the JWK.
 *
 * @rfc{7517,4.1}
 */
typedef enum {
	JWK_KEY_TYPE_NONE = 0,		/**< Unused on valid keys */
	JWK_KEY_TYPE_EC,		/**< Eliptic Curve keys */
	JWK_KEY_TYPE_RSA,		/**< RSA keys (RSA and RSA-PSS) */
	JWK_KEY_TYPE_OKP,		/**< Octet Key Pair (e.g. EDDSA) */
} jwk_key_type_t;

/** @ingroup jwks_core_grp
 * @brief Usage types for JWK public keys
 *
 * Corresponds to the ``"use"`` attribute in a valid JWK.
 *
 * @rfc{7517,4.2}
 **/
typedef enum {
	JWK_PUB_KEY_USE_NONE = 0,	/**< No usable attribute was set */
	JWK_PUB_KEY_USE_SIG,		/**< Signature validation (JWS) */
	JWK_PUB_KEY_USE_ENC,		/**< Decryption key (JWE) */
} jwk_pub_key_use_t;

/** @ingroup jwks_core_grp
 * @brief Allowed key operations for JWK private keys
 *
 * A JWK can support one or more of these bitwise flag  operations. The
 * names correspond with the RFC.
 *
 * @code
 * if (@ref jwt_item_t.key_ops & (JWK_KEY_OP_SIGN | JWK_KEY_OP_ENCRYPT)) {
 *     ...
 * }
 * @endcode
 *
 * @rfc{7517,4.3}
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

/** @ingroup jwks_core_grp
 * @brief Structural representation of a JWK
 *
 * This data structure is produced by importing a JWK or JWKS into a
 * @ref jwk_set_t object. Generally, you would not change any values here
 * and only use this to probe the internal parser and possibly to
 * decide whether a key applies to certain jwt_t for verification
 * or signing.
 *
 * @remark If the @ref jwk_item_t.pem field is not NULL, then it contains
 *  a nil terminated string of the key. The underlying crypto algorith may
 *  or may not support this. It's provided as a convenience.
 *
 * @raisewarning Decide if we need to make this an opaque object
 */
typedef struct {
	jwk_key_type_t kty;	/**< The key type of this key					*/
	char *pem;		/**< If not NULL, contains PEM string of this key		*/
	jwt_crypto_provider_t provider; /**< Crypto provider that owns this key			*/
	void *provider_data;	/**< Internal data used by the provider				*/
	int is_private_key;	/**< Whether this is a public or private key			*/
	char curve[256];	/**< Curve name of an ``"EC"`` or ``"OKP"`` key			*/
	size_t bits;		/**< The number of bits in the key (may be 0)			*/
	int error;		/**< Shows there is an error present in this key (unusable)	*/
	char error_msg[256];	/**< Descriptive message for @ref jwk_item_t.error		*/
	jwk_pub_key_use_t use;	/**< Value of the JWK ``"use"`` attribute			*/
	jwk_key_op_t key_ops;	/**< Bitwise flags of ``"key_ops"`` supported for this key	*/
	jwt_alg_t alg;		/**< Valid ``"alg"`` that this key can be used for		*/
	char *kid;		/**< @rfc{7517,4.5}						*/
} jwk_item_t;

/** @ingroup jwt_valid_grp
 * @brief Validation exception types for @ref jwt_t objects
 *
 * These are bitwise values that allow you to check for exceptions when using
 * the @ref jwt_valid_t
 *
 * @todo @rfc_t{7519,4.1.6} ``"iat"`` Issued At
 * @todo @rfc_t{7519,4.1.7} ``"jti"`` JWT ID
 */
typedef enum {
	JWT_VALIDATION_SUCCESS		= 0x0000,	/**< Validation succeeded			*/
	JWT_VALIDATION_ERROR		= 0x0001,	/**< General failures				*/
	JWT_VALIDATION_ALG_MISMATCH	= 0x0002,	/**< @rfc_t{7518,3.1} ``"alg"`` Algorithm	*/
	JWT_VALIDATION_EXPIRED		= 0x0004,	/**< @rfc_t{7519,4.1.4} ``"exp"`` Expired	*/
	JWT_VALIDATION_TOO_NEW		= 0x0008,	/**< @rfc_t{7519,4.1.5} ``"nbf"`` Not Before	*/
	JWT_VALIDATION_ISS_MISMATCH	= 0x0010,	/**< @rfc_t{7519,4.1.1} ``"iss"`` Issuer	*/
	JWT_VALIDATION_SUB_MISMATCH	= 0x0020,	/**< @rfc_t{7519,4.1.2} ``"sub"`` Subject	*/
	JWT_VALIDATION_AUD_MISMATCH	= 0x0040,	/**< @rfc_t{7519,4.1.3} ``"aud"`` Audience	*/
	JWT_VALIDATION_GRANT_MISSING	= 0x0080,	/**< User-defined Grant missing			*/
	JWT_VALIDATION_GRANT_MISMATCH	= 0x0100,	/**< User-defined Grant mismatch		*/
} jwt_valid_exception_t;

/** @ingroup jwt_memory_grp
 * @brief Prototype for malloc(3)
 */
typedef void *(*jwt_malloc_t)(size_t);

/** @ingroup jwt_memory_grp
 * @brief Prototype for realloc(3)
 */
typedef void *(*jwt_realloc_t)(void *, size_t);

/** @ingroup jwt_memory_grp
 * @brief Prototype for free(3)
 */
typedef void (*jwt_free_t)(void *);

/**
 * @defgroup jwt_grp JSON Web Token
 * @{
 */

/**
 * @defgroup jwt_core_grp Object Creation
 *
 * Functions used to create and destroy JWT objects.
 * @{
 */

/**
 * Allocate a new, empty, JWT object.
 *
 * This is used to create a new object that would be passed to one of
 * the @ref jwt_encode_grp functions once setup.
 *
 * @code
 * {
 *     jwt_t *MyJWT = NULL;
 *
 *     if (jwt_new(&MyJWT))
 *         ...handle error...
 *
 *     ...create JWT...
 *
 *     jwt_free(MyJWT);
 * }
 * @endcode
 *
 * @param jwt Pointer to a JWT object pointer. Will be allocated on
 *   success.
 * @return 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_new(jwt_t **jwt);

/**
 * Free a JWT object and any other resources it is using.
 *
 * After calling, the JWT object referenced will no longer be valid and
 * its memory will be freed.
 *
 * @param jwt Pointer to a JWT object previously created object
 */
JWT_EXPORT
void jwt_free(jwt_t *jwt);

#if defined(__GNUC__) || defined(__clang__)
/**
 * @raisewarning Document jwt_freep
 */
static inline void jwt_freep(jwt_t **jwt) {
	if (jwt) {
		jwt_free(*jwt);
		*jwt = NULL;
	}
}
#define jwt_auto_t jwt_t __attribute__((cleanup(jwt_freep)))
#endif

/**
 * Duplicate an existing JWT object.
 *
 * Copies all grants and algorithm specific bits to a new JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @return A new object on success, NULL on error with errno set
 *     appropriately.
 */
JWT_EXPORT
jwt_t *jwt_dup(jwt_t *jwt);

/**
 * @}
 * @noop jwt_core_grp
 */

/**
 * @defgroup jwt_config_grp Configuration Type
 *
 * The JWT configuration tools are setup to allow an agnostic way to handle
 * state between different functions. The specific uses of the tools varies
 * according to whether you are providing or consuming tokens. These aspects
 * are documented in the other sections.
 *
 * This section is a light intro of config types and common usage.
 *
 * @remark LibJWT does not internally modify or set information in the
 *  @ref jwt_config_t object. Certain values will determine how LibJWT
 *  handles various functions.
 * @{
 */

/**
 * @brief Structure used to manage configuration state
 */
typedef struct {
	union {
		const void *key;	/**< Pointer to key material	*/
		JWT_DEPRECATED const void *jwt_key;
	};
	union {
		size_t key_len;		/**< Length of key material	*/
		JWT_DEPRECATED int jwt_key_len;
	};
	jwt_alg_t alg;			/**< For algorithm matching	*/
	void *ctx;			/**< User controlled context	*/
} jwt_config_t;

/**
 * @brief Intialize @ref jwt_config_t to a clean state.
 *
 * To ensure a @ref jwt_config_t is at a known state, this will clear
 * values in the config. It will not free memory that might be associated
 * with internal pointers.
 *
 * @param config Pointer to config to be cleared
 */
JWT_EXPORT
void jwt_config_init(jwt_config_t *config);

/**
 * @brief Decleration of a @ref jwt_config_t
 *
 * This is useful for scoped usage to avoid declaring it and running the
 * @ref jwt_config_init function.
 *
 * @code
 * void some_function(const char *token)
 * {
 *     JWT_CONFIG_DECLARE(my_config);
 *     jwt_auto_t *my_jwt;
 *     int ret;
 *
 *     // Setup my_config with key, alg type, etc
 *
 *     ret = jwt_verify(&my_jwt, token, &my_config);
 *     if (ret)
 *         return ret;
 *
 *     // Success
 * }
 * @endcode
 */
#define JWT_CONFIG_DECLARE(__name) \
	jwt_config_t __name = { { NULL }, { 0 }, JWT_ALG_NONE, NULL}

/**
 * @brief Callback for operations involving verification of tokens.
 *
 * Further details can be found in @ref jwt_verify_grp, specifically
 * for @ref jwt_verify_wcb
 */
typedef int (*jwt_callback_t)(const jwt_t *, jwt_config_t *);

/**< @cond JWT_BACKWARD_COMPAT */
/**
 * @brief Backward compatibility for @ref jwt_decode_2
 */
#define jwt_key_p_t jwt_callback_t

/**
 * @brief Backward compatibility for @ref jwt_decode_2
 */
#define jwt_key_t jwt_config_t
/**< @endcond */

/**
 * @}
 * @noop jwt_config_grp
 */

/**
 * @defgroup jwt_verify_grp Token Verification
 * @{
 */

/**
 * @brief Decode and verify a JWT
 *
 * @raisewarning Complete documentation of jwt_verify
 *
 * @param jwt Pointer to a JWT object pointer
 * @param token Pointer to a nil terminated JWT string
 * @param config Pointer to a config structure to define how to verify the
 *   token
 * @return 0 on success, or an errno. On success, jwt will be allocated
 */
JWT_EXPORT
int jwt_verify(jwt_t **jwt, const char *token, jwt_config_t *config);

/**
 * @brief Decode and verify a JWT, with user callback
 *
 * This operates the same as @ref jwt_verify, with the addition of calling
 * a user defined callback function between the decode and verification step.
 * This allows the user to perform some extra verification, and even provide a
 * key after decoding (e.g. to match a ``"kid"``).
 *
 * @raisewarning Complete documentation of jwt_verify_wcb
 *
 * @param jwt Pointer to a JWT object pointer
 * @param token Pointer to a nil terminated JWT string
 * @param config Pointer to a config structure to define how to verify the
 *   token
 * @param cb Pointer to a callback
 * @return 0 on success, or an errno. On success, jwt will be allocated
 */
JWT_EXPORT
int jwt_verify_wcb(jwt_t **jwt, const char *token,
		   jwt_config_t *config, jwt_callback_t cb);

/**
 * @brief Decode a JWT
 *
 * @deprecated See @ref jwt_verify instead.
 *
 * @param jwt Pointer to a JWT object pointer
 * @param token Pointer to a nil terminated JWT string
 * @param key Pointer to key
 * @param key_len The length of the above key.
 * @return 0 on success, or an errno. On success, jwt will be allocated
 */
JWT_DEPRECATED_EXPORT
int jwt_decode(jwt_t **jwt, const char *token,
	       const unsigned char *key, int key_len);

/**
 * @brief Decode a JWT with a user provided callback
 *
 * @deprecated See @ref jwt_verify_wcb instead.
 *
 * @param jwt Pointer to a JWT object pointer
 * @param token Pointer to a nil terminated JWT string
 * @param cb Pointer to a callback
 * @return 0 on success, or an errno. On success, jwt will be allocated
 */
JWT_DEPRECATED_EXPORT
int jwt_decode_2(jwt_t **jwt, const char *token,
		 jwt_callback_t cb);

/**
 * @}
 * @noop jwt_verify_grp
 */

/**
 * @defgroup jwt_grant_grp Grant Management
 * These functions allow you to add, remove and retrieve grants from a JWT
 * object.
 * @{
 */

/**
 * Return the value of a string grant.
 *
 * Returns the string value for a grant (e.g. "iss"). If it does not exist,
 * NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a string for the value, or NULL when not found.
 *
 * @remark This will only return grants with JSON string values. Use
 *   jwt_get_grants_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_grant_int() to get simple integer
 *   values.
 */
JWT_EXPORT
const char *jwt_get_grant(jwt_t *jwt, const char *grant);

/**
 * Return the value of an integer grant.
 *
 * Returns the int value for a grant (e.g. "exp"). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns an int for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return grants with JSON integer values. Use
 *   jwt_get_grants_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_grant() to get string values.
 */
JWT_EXPORT
long jwt_get_grant_int(jwt_t *jwt, const char *grant);

/**
 * Return the value of an boolean grant.
 *
 * Returns the int value for a grant (e.g. "exp"). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a boolean for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return grants with JSON boolean values. Use
 *   jwt_get_grants_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_grant() to get string values.
 */
JWT_EXPORT
int jwt_get_grant_bool(jwt_t *jwt, const char *grant);

/**
 * Return the value of a grant as JSON encoded object string.
 *
 * Returns the JSON encoded string value for a grant (e.g. "iss"). If it
 * does not exist, NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *     for. If this is NULL, all grants will be returned as a JSON encoded
 *     hash.
 * @return Returns a string for the value, or NULL when not found. The
 *     returned string must be freed by the caller.
 */
JWT_EXPORT
char *jwt_get_grants_json(jwt_t *jwt, const char *grant);

/**
 * Add a new string grant to this JWT object.
 *
 * Creates a new grant for this object. The string for grant and val
 * are copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a grant that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to add.
 * @param val String containing the value to be saved for grant. Can be
 *     an empty string, but cannot be NULL.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for string based grants. If you wish to add
 *   integer grants, then use jwt_add_grant_int(). If you wish to add more
 *   complex grants (e.g. an array), then use jwt_add_grants_json().
 */
JWT_EXPORT
int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val);

/**
 * Add a new integer grant to this JWT object.
 *
 * Creates a new grant for this object. The string for grant
 * is copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a grant that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to add.
 * @param val int containing the value to be saved for grant.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for integer based grants. If you wish to add
 *   string grants, then use jwt_add_grant(). If you wish to add more
 *   complex grants (e.g. an array), then use jwt_add_grants_json().
 */
JWT_EXPORT
int jwt_add_grant_int(jwt_t *jwt, const char *grant, long val);

/**
 * Add a new boolean grant to this JWT object.
 *
 * Creates a new grant for this object. The string for grant
 * is copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a grant that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to add.
 * @param val boolean containing the value to be saved for grant.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for boolean based grants. If you wish to add
 *   string grants, then use jwt_add_grant(). If you wish to add more
 *   complex grants (e.g. an array), then use jwt_add_grants_json().
 */
JWT_EXPORT
int jwt_add_grant_bool(jwt_t *jwt, const char *grant, int val);

/**
 * Add grants from a JSON encoded object string.
 *
 * Loads a grant from an existing JSON encoded object string. Overwrites
 * existing grant. If grant is NULL, then the JSON encoded string is
 * assumed to be a JSON hash of all grants being added and will be merged
 * into the grant listing.
 *
 * @param jwt Pointer to a JWT object.
 * @param json String containing a JSON encoded object of grants.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_add_grants_json(jwt_t *jwt, const char *json);

/**
 * Delete a grant from this JWT object.
 *
 * Deletes the named grant from this object. It is not an error if there
 * is no grant matching the passed name. If grant is NULL, then all grants
 * are deleted from this JWT.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to delete. If this
 *    is NULL, then all grants are deleted.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_del_grants(jwt_t *jwt, const char *grant);

/**
 * @}
 * @noop jwt_grant_grp
 */

/**
 * @defgroup jwt_header_grp Header Hanagement
 * These functions allow you to add, remove and retrieve headers from a JWT
 * object.
 * @{
 */

/**
 * Return the value of a string header.
 *
 * Returns the string value for a header (e.g. ""). If it does not exist,
 * NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to return a value
 *     for.
 * @return Returns a string for the value, or NULL when not found.
 *
 * @remark This will only return headers with JSON string values. Use
 *   jwt_get_header_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_header_int() to get simple integer
 *   values.
 */
JWT_EXPORT
const char *jwt_get_header(jwt_t *jwt, const char *header);

/**
 * Return the value of an integer header.
 *
 * Returns the int value for a header (e.g. ""). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to return a value
 *     for.
 * @return Returns an int for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return headers with JSON integer values. Use
 *   jwt_get_header_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_header() to get string values.
 */
JWT_EXPORT
long jwt_get_header_int(jwt_t *jwt, const char *header);

/**
 * Return the value of an boolean header.
 *
 * Returns the int value for a header (e.g. ""). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to return a value
 *     for.
 * @return Returns a boolean for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return headers with JSON boolean values. Use
 *   jwt_get_header_json() to get the JSON representation of more complex
 *   values (e.g. arrays) or use jwt_get_header() to get string values.
 */
JWT_EXPORT
int jwt_get_header_bool(jwt_t *jwt, const char *header);

/**
 * Return the value of a header as JSON encoded object string.
 *
 * Returns the JSON encoded string value for a header (e.g. ""). If it
 * does not exist, NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to return a value
 *     for. If this is NULL, all headers will be returned as a JSON encoded
 *     hash.
 * @return Returns a string for the value, or NULL when not found. The
 *     returned string must be freed by the caller.
 */
JWT_EXPORT
char *jwt_get_headers_json(jwt_t *jwt, const char *header);

/**
 * Add a new string header to this JWT object.
 *
 * Creates a new header for this object. The string for header and val
 * are copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a header that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to add.
 * @param val String containing the value to be saved for header. Can be
 *     an empty string, but cannot be NULL.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for string based headers. If you wish to add
 *   integer headers, then use jwt_add_header_int(). If you wish to add more
 *   complex headers (e.g. an array), then use jwt_add_headers_json().
 */
JWT_EXPORT
int jwt_add_header(jwt_t *jwt, const char *header, const char *val);

/**
 * Add a new integer header to this JWT object.
 *
 * Creates a new header for this object. The string for header
 * is copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a header that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to add.
 * @param val int containing the value to be saved for header.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for integer based headers. If you wish to add
 *   string headers, then use jwt_add_header(). If you wish to add more
 *   complex headers (e.g. an array), then use jwt_add_headers_json().
 */
JWT_EXPORT
int jwt_add_header_int(jwt_t *jwt, const char *header, long val);

/**
 * Add a new boolean header to this JWT object.
 *
 * Creates a new header for this object. The string for header
 * is copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a header that already exists.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to add.
 * @param val boolean containing the value to be saved for header.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for boolean based headers. If you wish to add
 *   string headers, then use jwt_add_header(). If you wish to add more
 *   complex headers (e.g. an array), then use jwt_add_headers_json().
 */
JWT_EXPORT
int jwt_add_header_bool(jwt_t *jwt, const char *header, int val);

/**
 * Add headers from a JSON encoded object string.
 *
 * Loads a header from an existing JSON encoded object string. Overwrites
 * existing header. If header is NULL, then the JSON encoded string is
 * assumed to be a JSON hash of all headers being added and will be merged
 * into the header listing.
 *
 * @param jwt Pointer to a JWT object.
 * @param json String containing a JSON encoded object of headers.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_add_headers_json(jwt_t *jwt, const char *json);

/**
 * Delete a header from this JWT object.
 *
 * Deletes the named header from this object. It is not an error if there
 * is no header matching the passed name. If header is NULL, then all headers
 * are deleted from this JWT.
 *
 * @param jwt Pointer to a JWT object.
 * @param header String containing the name of the header to delete. If this
 *    is NULL, then all headers are deleted.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_del_headers(jwt_t *jwt, const char *header);

/**
 * @}
 * @noop jwt_header_grp
 */

/**
 * @defgroup jwt_encode_grp Encoding and Output
 * Functions for encoding a valid JWT optionally (but preferably) using
 * JWA operation such as sigining or encryption.
 * @{
 */

/**
 * Output plain text representation to a FILE pointer.
 *
 * This function will write a plain text representation of this JWT object
 * without Base64 encoding. This only writes the header and body, and does
 * not compute the signature or encryption (if such an algorithm were being
 * used).
 *
 * @remark This may change the content of JWT header if algorithm is set
 *   on the JWT object. If algorithm is set (jwt_set_alg was called
 *   on the jwt object) then dumping JWT attempts to append 'typ' header.
 *   If the 'typ' header already exists, then it is left untouched,
 *   otherwise it is added with default value of "JWT".
 *
 * @param jwt Pointer to a JWT object.
 * @param fp Valid FILE pointer to write data to.
 * @param pretty Enables better visual formatting of output. Generally only
 *     used for debugging.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty);

/**
 * Return plain text representation as a string.
 *
 * Similar to jwt_dump_fp() except that a string is returned. The string
 * must be freed by the caller.
 *
 * @remark This may change the content of JWT header if algorithm is set
 *   on the JWT object. If algorithm is set (jwt_set_alg was called
 *   on the jwt object) then dumping JWT attempts to append 'typ' header.
 *   If the 'typ' header already exists, then it is left untouched,
 *   otherwise it is added with default value of "JWT".
 *
 * @param jwt Pointer to a JWT object.
 * @param pretty Enables better visual formatting of output. Generally only
 *     used for debugging.
 * @return A nul terminated string on success, NULL on error with errno
 *     set appropriately.
 */
JWT_EXPORT
char *jwt_dump_str(jwt_t *jwt, int pretty);

/**
 * Return plain text representation of grants as a string.
 *
 * Similar to jwt_dump_str() except that only a string containing the
 * grants string is returned. The string must be freed by the caller.
 *
 * @param jwt Pointer to a JWT object.
 * @param pretty Enables better visual formatting of output. Generally only
 *     used for debugging.
 * @return A nul terminated string on success, NULL on error with errno
 *     set appropriately.
 */
JWT_EXPORT
char *jwt_dump_grants_str(jwt_t *jwt, int pretty);

/**
 * Fully encode a JWT object and write it to FILE.
 *
 * This will create and write the complete JWT object to FILE. All parts
 * will be Base64 encoded and signatures or encryption will be applied if
 * the algorithm specified requires it.
 *
 * @param jwt Pointer to a JWT object.
 * @param fp Valid FILE pointer to write data to.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_encode_fp(jwt_t *jwt, FILE *fp);

/**
 * Fully encode a JWT object and return as a string.
 *
 * Similar to jwt_encode_fp() except that a string is returned. The string
 * must be freed by the caller. If you changed the allocation method using
 * jwt_set_alloc, then you must use jwt_free_str() to free the memory.
 *
 * @param jwt Pointer to a JWT object.
 * @return A null terminated string on success, NULL on error with errno
 *     set appropriately.
 */
JWT_EXPORT
char *jwt_encode_str(jwt_t *jwt);

/**
 * Free a string returned from the library.
 *
 * @param str Pointer to a string previously created with
 *     jwt_encode_str().
 */
JWT_EXPORT
void jwt_free_str(char *str);

/**
 * @}
 * @noop jwt_encode_grp
 */

/**
 * @defgroup jwt_alg_grp Algorithm Management
 * Set and check algorithms and algorithm specific values.
 *
 * When working with functions that require a key, the underlying library
 * takes care to scrub memory when the key is no longer used (e.g. when
 * calling jwt_free() or when changing the algorithm, the old key, if it
 * exists, is scrubbed).
 * @{
 */

/**
 * Set an algorithm for a @ref jwt_t object.
 *
 * Specifies an algorithm for a @ref jwt_t object. If @ref JWT_ALG_NONE is used,
 * then key must be NULL and len must be 0. All other algorithms must have a
 * valid pointer to key data, which may be specific to the algorithm (e.g
 * RS256 expects a PEM formatted RSA key).
 *
 * @param jwt Pointer to a @ref jwt_t object.
 * @param alg A valid @ref jwt_alg_t specifier.
 * @param key The key data to use for the algorithm.
 * @param len The length of the key data.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, const unsigned char *key, int len);

/**
 * Get the jwt_alg_t set for this JWT object.
 *
 * Returns the jwt_alg_t type for this JWT object.
 *
 * @warning This is the alg for the jwt_t object and NOT the one that may
 * be set in the header. This is a programatic check to see what LibJWT
 * will use to encode the object into a JWT. To see what is embedded in
 * the header, use jwt_get_header(jwt, "alg") instead.
 *
 * @param jwt Pointer to a JWT object.
 * @returns Returns a jwt_alg_t type for this object.
 */
JWT_EXPORT
jwt_alg_t jwt_get_alg(const jwt_t *jwt);

/**
 * Convert alg type to it's string representation.
 *
 * Returns a string that matches the alg type provided.
 *
 * @param alg A valid jwt_alg_t specifier.
 * @returns Returns a string (e.g. "RS256") matching the alg or NULL for
 *     invalid alg.
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
 * or @ref JWT_ALG_INVAL if no  matches were found.
 *
 * Note, this only works for algorithms that LibJWT supports or knows about.
 */
JWT_EXPORT
jwt_alg_t jwt_str_alg(const char *alg);

/**
 * @}
 * @noop jwt_alg_grp
 */

/**
 * @}
 * @noop jwt_grp
 */

/**
 * @defgroup jwks_core_grp JSON Web Key and Sets
 * Functions to handle JSON that represents JWK and JWKS for use
 * in validating JWT objects.
 * @{
 */

/**
 * Create a new JWKS object for later use in validating JWTs.
 *
 * This function expects a JSON string either as a single object
 * for one JWK or as an array of objects under a key of "keys" (as
 * defined in JWKS specifications).
 *
 * If non-NULL is returned, you should then check to make sure there
 * is no error with jwks_error(). There may be errors on individual
 * JWK items in the set. You can check if there are any with
 * jwks_error_any().
 *
 * @param jwk_json_str JSON string representation of a single key
 *   or array of "keys". If NULL is passed, an empty jwk_set_t is
 *   created.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 */
JWT_EXPORT
jwk_set_t *jwks_create(const char *jwk_json_str);

/**
 * Add a jwk_item_t to an existing jwk_set_t
 *
 * @param jwk_set An existing jwk_set_t
 * @param item A JWK item to add to the set
 * @return 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwks_item_add(jwk_set_t *jwk_set, jwk_item_t *item);

/**
 * Check if there is an error within the jwk_set
 *
 * To get a string describing the error, use jwks_error_str.
 *
 * @param jwk_set An existing jwk_set_t
 * @return 0 if no error exists, 1 if it does exists.
 */
JWT_EXPORT
int jwks_error(jwk_set_t *jwk_set);

/**
 * Check if there is an error within the jwk_set and any of
 * the jwk_item_t in the set.
 *
 * @param jwk_set An existing jwk_set_t
 * @return 0 if no error exists, 1 if any exists.
 */
JWT_EXPORT
int jwks_error_any(jwk_set_t *jwk_set);

/**
 * Retrieve an error message from a jwk_set. Note, a zero
 * length string is valid if jwos_error() returns non-zero.
 *
 * @param jwk_set An existing jwk_set_t
 * @return NULL on error, valid string otherwise
 */
JWT_EXPORT
const char *jwks_error_msg(jwk_set_t *jwk_set);

/**
 * Return the index'th jwk_item in the jwk_set
 *
 * Allows you to obtain the raw jwk_item. NOTE, this is not a copy
 * of the item, so any changes to it will be reflected to it in the
 * jwk_set. This also means if the jwk_set is freed, then this data
 * is freed and cannot be used.
 *
 * @param jwk_set An existing jwk_set_t
 * @param index Index of the jwk_set
 * @return 0 if no error exists, 1 if it does exists.
 *
 * @remark It's also worth pointing out that the index of a specific
 *     jwk_item in a jwk_set can and will change if items are added or
 *     removed.
 * from the jwk_set.
 */
JWT_EXPORT
jwk_item_t *jwks_item_get(jwk_set_t *jwk_set, size_t index);

/**
 * Free all memory associated with a jwt_set_t, including any
 * jwk_item_t in the set
 *
 * @param jwk_set An existing jwk_set_t
 */
JWT_EXPORT
void jwks_free(jwk_set_t *jwk_set);

/**
 * Free all memory associated with the nth jwt_item_t in a jwk_set
 *
 * @param jwk_set A JWKS object
 * @param index the position of the item in the index
 * @return 0 if no item was was deleted (found), 1 if it was
 */
JWT_EXPORT
int jwks_item_free(jwk_set_t *jwk_set, size_t index);

/**
 * Free all memory associated with alljwt_item_t in a jwk_set. The
 * jwk_set becomes an empty set.
 *
 * @param jwk_set A JWKS object
 * @return The numbner of items deleted
 */
JWT_EXPORT
int jwks_item_free_all(jwk_set_t *jwk_set);

/**
 * @}
 * @noop jwks_core_grp
 */

/** @ingroup jwt_grp
 * @defgroup jwt_valid_grp Validation Functions
 * These functions allow you to define requirements for JWT validation.
 *
 * The most basic validation is that the JWT uses the expected algorithm.
 *
 * When replicating claims in header (usually for encrypted JWT), validation
 * tests that they match claims in the body (iss, sub, aud).
 *
 * Time-based claims can also be validated (nbf, exp).
 *
 * Finally, validation can test that claims be present and have certain value.
 *
 * @{
 */

/**
 * Validate a JWT object with a validation object.
 *
 * @param jwt Pointer to a JWT object.
 * @param jwt_valid Pointer to a JWT validation object.
 *
 * @return bitwide OR if possible validation errors or 0 on success
 */
JWT_EXPORT
jwt_valid_exception_t jwt_validate(jwt_t *jwt, jwt_valid_t *jwt_valid);

/**
 * Allocate a new, JWT validation object.
 *
 * This is used to create a new object for a JWT validation. After you have
 * finished with the object, use jwt_valid_free() to clean up the memory used by
 * it.
 *
 * @param jwt_valid Pointer to a JWT validation object pointer. Will be allocated
 *     on success.
 * @param alg A valid jwt_alg_t specifier.
 * @return 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_valid_new(jwt_valid_t **jwt_valid, jwt_alg_t alg);

/**
 * Free a JWT validation object and any other resources it is using.
 *
 * After calling, the JWT validation object referenced will no longer be valid
 * and its memory will be freed.
 *
 * @param jwt_valid Pointer to a JWT validation object previously created with
 *     jwt_valid_new().
 */
JWT_EXPORT
void jwt_valid_free(jwt_valid_t *jwt_valid);

/**
 * Return the status string for the validation object.
 *
 * The status of validation object is primarily for describing the reason
 * jwt_validate() failed.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @return Returns current validation status as a bitwise OR of possible
 *   errors, or 0 if validation is currently successful.
 */
JWT_EXPORT
jwt_valid_exception_t jwt_valid_get_status(jwt_valid_t *jwt_valid);

/**
 * Return the nbf_leeway value set.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @return Returns current nbf_leeway value
 */
JWT_EXPORT
time_t jwt_valid_get_nbf_leeway(jwt_valid_t *jwt_valid);

/**
 * Return the exp_leeway value set.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @return Returns current exp_leeway value
 */
JWT_EXPORT
time_t jwt_valid_get_exp_leeway(jwt_valid_t *jwt_valid);

/**
 * Add a new string grant requirement to this JWT validation object.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to add.
 * @param val String containing the value to be saved for grant. Can be
 *     an empty string, but cannot be NULL.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * Note, this only allows for string based grants. If you wish to add
 * integer grants, then use jwt_valid_add_grant_int(). If you wish to add more
 * complex grants (e.g. an array), then use jwt_valid_add_grants_json().
 */
JWT_EXPORT
int jwt_valid_add_grant(jwt_valid_t *jwt_valid, const char *grant, const char *val);

/**
 * Return the value of a string required grant.
 *
 * Returns the string value for a grant (e.g. "iss"). If it does not exist,
 * NULL will be returned.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a string for the value, or NULL when not found.
 *
 * Note, this will only return grants with JSON string values. Use
 * jwt_valid_get_grants_json() to get the JSON representation of more complex
 * values (e.g. arrays) or use jwt_valid_get_grant_int() to get simple integer
 * values.
 */
JWT_EXPORT
const char *jwt_valid_get_grant(jwt_valid_t *jwt_valid, const char *grant);

/**
 * Add a new integer grant requirement to this JWT validation object.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to add.
 * @param val int containing the value to be saved for grant.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for integer based grants. If you wish to add
 * string grants, then use jwt_valid_add_grant(). If you wish to add more
 * complex grants (e.g. an array), then use jwt_valid_add_grants_json().
 */
JWT_EXPORT
int jwt_valid_add_grant_int(jwt_valid_t *jwt_valid, const char *grant, long val);

/**
 * Return the value of an integer required grant.
 *
 * Returns the int value for a grant (e.g. "exp"). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns an int for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return grants with JSON integer values. Use
 * jwt_valid_get_grants_json() to get the JSON representation of more complex
 * values (e.g. arrays) or use jwt_valid_get_grant() to get string values.
 */
JWT_EXPORT
long jwt_valid_get_grant_int(jwt_valid_t *jwt_valid, const char *grant);

/**
 * Add a new boolean required grant to this JWT validation object.
 *
 * Creates a new grant for this object. The string for grant
 * is copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object. It is an error if you
 * try to add a grant that already exists.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to add.
 * @param val boolean containing the value to be saved for grant.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark This only allows for boolean based grants. If you wish to add
 * string grants, then use jwt_valid_add_grant(). If you wish to add more
 * complex grants (e.g. an array), then use jwt_valid_add_grants_json().
 */
JWT_EXPORT
int jwt_valid_add_grant_bool(jwt_valid_t *jwt_valid, const char *grant, int val);

/**
 * Return the value of an boolean required grant.
 *
 * Returns the int value for a grant (e.g. "exp"). If it does not exist,
 * 0 will be returned.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a boolean for the value. Sets errno to ENOENT when not
 * found.
 *
 * @remark This will only return grants with JSON boolean values. Use
 * jwt_valid_get_grants_json() to get the JSON representation of more complex
 * values (e.g. arrays) or use jwt_valid_get_grant() to get string values.
 */
JWT_EXPORT
int jwt_valid_get_grant_bool(jwt_valid_t *jwt_valid, const char *grant);

/**
 * Add required grants from a JSON encoded object string.
 *
 * Loads a grant from an existing JSON encoded object string. Overwrites
 * existing grant.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param json String containing a JSON encoded object of grants.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_valid_add_grants_json(jwt_valid_t *jwt_valid, const char *json);

/**
 * Return the value of a grant as JSON encoded object string.
 *
 * Returns the JSON encoded string value for a grant (e.g. "iss"). If it
 * does not exist, NULL will be returned.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a string for the value, or NULL when not found. The
 *     returned string must be freed by the caller.
 */
JWT_EXPORT
char* jwt_valid_get_grants_json(jwt_valid_t *jwt_valid, const char *grant);

/**
 * Delete a grant from this JWT object.
 *
 * Deletes the named grant from this object. It is not an error if there
 * is no grant matching the passed name. If grant is NULL, then all grants
 * are deleted from this JWT.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param grant String containing the name of the grant to delete. If this
 *    is NULL, then all grants are deleted.
 * @return Returns 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_valid_del_grants(jwt_valid_t *jwt_valid, const char *grant);

/**
 * Set the time for which expires and not-before claims should be evaluated.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param now Time to use when considering nbf and exp claims.
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark jwt_validate() will not fail based on time if no expires or
 *     not-before claims exist in a JWT object.
 */
JWT_EXPORT
int jwt_valid_set_now(jwt_valid_t *jwt_valid, const time_t now);

/**
 * Set the nbf_leeway value as defined in: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param nbf_leeway leeway for nbf value.
 * @return Returns 0 on success, valid errno otherwise.
 *
 */
JWT_EXPORT
int jwt_valid_set_nbf_leeway(jwt_valid_t *jwt_valid, const time_t nbf_leeway);

/**
 * Set the exp_leeway value as defined in: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param exp_leeway leeway for exp value.
 * @return Returns 0 on success, valid errno otherwise.
 *
 */
JWT_EXPORT
int jwt_valid_set_exp_leeway(jwt_valid_t *jwt_valid, const time_t exp_leeway);

/**
 * Set validation for replicated claims in headers.
 *
 * When set, validation tests for presence of iss, sub, aud in jwt headers and
 * tests match for same claims in body.
 *
 * @param jwt_valid Pointer to a JWT validation object.
 * @param hdr When true, test header claims
 * @return Returns 0 on success, valid errno otherwise.
 *
 * @remark jwt_validate() will not fail if iss, sub, aud are not present in JWT
 *     header or body.
 */
JWT_EXPORT
int jwt_valid_set_headers(jwt_valid_t *jwt_valid, int hdr);

/**
 * Parses exceptions and returns a comma delimited and human-readable string.
 *
 * The returned string must be freed by the caller. If you changed the allocation
 * method using jwt_set_alloc, then you must use jwt_free_str() to free the memory.
 *
 * @remark This string is currently en-US ASCII only. Language support will come in the
 * future.
 *
 * @param exceptions Integer containing the exception flags.
 * @return A null terminated string on success, NULL on error with errno
 *     set appropriately.
 */
JWT_EXPORT
char *jwt_exception_str(jwt_valid_exception_t exceptions);

/**
 * @}
 * @noop jwt_valid_grp
 */

/**
 * @defgroup jwt_advanced_grp Advanced Functionality
 * @{
 */

/**
 * @defgroup jwt_memory_grp Memory Handlers
 * These functions allow you to get or set memory allocation functions.
 * @{
 */

 /**
  * Set functions to be used for allocating and freeing memory.
  *
  * By default, LibJWT uses malloc, realloc, and free for memory
  * management. This function allows the user of the library to
  * specify its own memory management functions. This is especially
  * useful on Windows where mismatches in runtimes across DLLs can
  * cause problems.
  *
  * The caller can specify either a valid function pointer for
  * any of the parameters or NULL to use the corresponding default
  * allocator function.
  *
  * Note that this function will also set the memory allocator
  * for the Jansson library.
  *
  * @param pmalloc The function to use for allocating memory or
  *     NULL to use malloc
  * @param prealloc The function to use for reallocating memory or
  *     NULL to use realloc
  * @param pfree The function to use for freeing memory or
  *     NULL to use free
  * @returns 0 on success or errno otherwise.
  */
JWT_EXPORT
int jwt_set_alloc(jwt_malloc_t pmalloc, jwt_realloc_t prealloc,
			 jwt_free_t pfree);

/**
 * Get functions used for allocating and freeing memory.
 *
 * @param pmalloc Pointer to malloc function output variable, or NULL
 * @param prealloc Pointer to realloc function output variable, or NULL
 * @param pfree Pointer to free function output variable, or NULL
 */
JWT_EXPORT
void jwt_get_alloc(jwt_malloc_t *pmalloc, jwt_realloc_t *prealloc,
			  jwt_free_t *pfree);

 /**
  * @}
  * @noop jwt_memory_grp
  */

/**
 * @defgroup jwt_crypto_grp Cryptographic Operations
 * Functions used to set and get which crypto operations are used
 *
 * LibJWT supports several crypto libraries, mainly "openssl" and "gnutls".
 * By default, if enabled, "openssl" is used.
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
 */
JWT_EXPORT
const char *jwt_get_crypto_ops(void);

/**
 * Retrieve the type of the current crypto operations being used.
 *
 * @return jwt_crypto_provider_t of the crypto operation set
 */
JWT_EXPORT
jwt_crypto_provider_t jwt_get_crypto_ops_t(void);

/**
 * Set the crypto operations to the named set.
 *
 * The opname is one of the available operators in the compiled version
 * of LibJWT. Most times, this is either "openssl" or "gnutls".
 *
 * @param opname the name of the crypto operation to set
 * @return 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_set_crypto_ops(const char *opname);

/**
 * Set the crypto operations to a jwt_crypto_provider_t type
 *
 * The same as jwt_set_crypto_ops(), but uses the type as opname
 *
 * @param opname A valid jwt_crypto_provider_t type
 * @return 0 on success, valid errno otherwise.
 */
JWT_EXPORT
int jwt_set_crypto_ops_t(jwt_crypto_provider_t opname);

/**
 * Check if the current crypto operations support JWK usage
 *
 * @return 1 if it does, 0 if not
 */
JWT_EXPORT
int jwt_crypto_ops_supports_jwk(void);

/**
 * @}
 * @noop jwt_crypto_grp
 */

/**
 * @}
 * @noop advanced_grp
 */

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
