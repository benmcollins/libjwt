/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
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
	JWT_CRYPTO_OPS_ANY,		/**< Used internally for hmac keys */
} jwt_crypto_provider_t;

/** @ingroup jwks_core_grp
 * @brief JWK Key Types
 *
 * Corresponds to the ``"kty"`` attribute of the JWK.
 *
 * @rfc{7517,4.1}
 * @rfc{7518,6.1}
 */
typedef enum {
	JWK_KEY_TYPE_NONE = 0,		/**< Unused on valid keys */
	JWK_KEY_TYPE_EC,		/**< Eliptic Curve keys */
	JWK_KEY_TYPE_RSA,		/**< RSA keys (RSA and RSA-PSS) */
	JWK_KEY_TYPE_OKP,		/**< Octet Key Pair (e.g. EdDSA) */
	JWK_KEY_TYPE_OCT,		/**< Octet sequence (e.g. HS256) */
} jwk_key_type_t;

/** @ingroup jwks_core_grp
 * @brief Usage types for JWK public keys
 *
 * Corresponds to the ``"use"`` attribute in a JWK the represents a public key.
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
 * Corresponds to the ``"key_ops"`` attribute in a JWK that represents a private
 * key. These can be bitwise compares to the key_ops attribute of a @ref
 * jwk_item_t. These flags are used internally to decide if a JWK can be used
 * for cartain operations.
 *
 * @code
 * if (jwk_item_t.key_ops & (JWK_KEY_OP_SIGN | JWK_KEY_OP_ENCRYPT)) {
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
 * @brief Object representation of a JWK
 *
 * This object is produced by importing a JWK or JWKS into a  @ref jwk_set_t
 * object. It is passed functions that either producr or consume JWT.
 */
typedef struct jwk_item jwk_item_t;

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
JWT_VALIDATION_SUCCESS		= 0x0000, /**< Validation succeeded			*/
JWT_VALIDATION_ERROR		= 0x0001, /**< General failures				*/
JWT_VALIDATION_ALG_MISMATCH	= 0x0002, /**< @rfc_t{7518,3.1} ``"alg"`` Algorithm	*/
JWT_VALIDATION_EXPIRED		= 0x0004, /**< @rfc_t{7519,4.1.4} ``"exp"`` Expired	*/
JWT_VALIDATION_TOO_NEW		= 0x0008, /**< @rfc_t{7519,4.1.5} ``"nbf"`` Not Before	*/
JWT_VALIDATION_ISS_MISMATCH	= 0x0010, /**< @rfc_t{7519,4.1.1} ``"iss"`` Issuer	*/
JWT_VALIDATION_SUB_MISMATCH	= 0x0020, /**< @rfc_t{7519,4.1.2} ``"sub"`` Subject	*/
JWT_VALIDATION_AUD_MISMATCH	= 0x0040, /**< @rfc_t{7519,4.1.3} ``"aud"`` Audience	*/
JWT_VALIDATION_GRANT_MISSING	= 0x0080, /**< User-defined Grant missing		*/
JWT_VALIDATION_GRANT_MISMATCH	= 0x0100, /**< User-defined Grant mismatch		*/
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
 * @defgroup jwt_core_grp Object Management
 *
 * Utility functions for JWT objects.
 * @{
 */

/**
 * @brief Check JWT for error condition
 *
 * The relevance of this is dependent on whether this is a JWT being created,
 * or one being verified. See those functions for more information. Either way,
 * if a JWT has an error, it cannot be trusted.
 *
 * @param jwt Pointer to a jwt_t object
 * @return 0 if no error, 1 if there is
 *
 * @remark When creating a JWT and verifying one, you shoudl always check this
 *  state.
 */
JWT_EXPORT
int jwt_error(const jwt_t *jwt);

/**
 * @brief Print an error message from a JWT
 *
 * If jwt_error() shows an an error condition, this will give you a better idea
 * of the actual error being reported.
 *
 * @param jwt Pointer to a jwt_t object
 * @return A string message. The string may be empty.
 */
JWT_EXPORT
const char *jwt_error_msg(const jwt_t *jwt);

/**
 * @brief Free a JWT object and any other resources it is using.
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
 * @brief Helper function to free a JWT and set the pointer to NULL
 *
 * This is mainly to use with the jwt_auto_t type.
 *
 * @param Pointer to a pointer for a jwt_t object
 */
static inline void jwt_freep(jwt_t **jwt) {
	if (jwt) {
		jwt_free(*jwt);
		*jwt = NULL;
	}
}
/**
 * @brief Scoped cleanup type for jwt_t
 *
 * Declaring a jwt_t with jwt_auto_t will ensure that the memory used by it is
 * cleaned up when the variable goes our of scope (e.g. when a function
 * returns).
 *
 * @warning Make sure to initialize thsi to NULL when declaring with this type.
 *
 * @code
 * void my_app_check_token(const char *token)
 * {
 *     jwt_auto_t *myjwt = NULL;
 *
 *     // ...
 *
 *     myjwt = jwt_create(NULL);
 *
 *     // ...
 *
 *     return; // myjwt will be freed here automatically
 * }
 * @endcode
 */
#define jwt_auto_t jwt_t __attribute__((cleanup(jwt_freep)))
#endif

/**
 * Duplicate an existing JWT object.
 *
 * Copies all grants and algorithm specific bits to a new JWT object. This
 * includes the JWK that is associated with it, if it exists. However, the JWT
 * is only copied by reference, and is not, itself, duplicated.
 *
 * @param jwt Pointer to a JWT object.
 * @return A new object on success, NULL on error with errno set appropriately.
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
 * The JWT configuration type is setup to allow an agnostic way to handle
 * state between different functions. The specific uses of the type varies
 * according to whether you are providing or consuming tokens. These aspects
 * are documented in the other sections.
 *
 * This section is a light intro of config type and common usage.
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
	const jwk_item_t *jw_key;	/**< A JWK to use for key	*/
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
 *     my_jwt = jwt_verify(token, &my_config);
 *     if (my_jwt == NULL || jwt_error(my_jwt))
 *         ...;
 *
 *     // Success
 * }
 * @endcode
 */
#define JWT_CONFIG_DECLARE(__name) \
	jwt_config_t __name = { NULL, JWT_ALG_NONE, NULL}

/**
 * @brief Callback for operations involving verification of tokens.
 *
 * Further details can be found in @ref jwt_verify_grp, specifically
 * for @ref jwt_verify_wcb
 */
typedef int (*jwt_callback_t)(const jwt_t *, jwt_config_t *);

/**
 * @}
 * @noop jwt_config_grp
 */

/**
 * @defgroup jwt_create_grp Creation
 *
 * @raisewarning Complete overview of JWT create group
 * @{
 */

/**
 * @brief Initial function to create a new JWT
 *
 * @raisewarning Complete documentation of jwt_create
 */
JWT_EXPORT
jwt_t *jwt_create(jwt_config_t *config);

/**
 * @}
 * @noop jwt_create_grp
 */

/**
 * @defgroup jwt_verify_grp Verification
 *
 * LibJWT provides mechanisms to verify a JWT including the signature block.
 * Many aspects of this verification are defined by the relevant RFCs.
 *
 * @raisewarning Need more indepth information
 *
 * @{
 */

/**
 * @brief Decode and verify a JWT
 *
 * In order to verify a token, the config param MUST set jw_key and alg. Both
 * are required. On return, you should inspect the resulting jwt_t for error
 * using jwt_error(). You can print a message with jwt_error_msg().
 *
 * In order to verify, several things must be true:
 * - The value of config.alg MUST match the value of alg in the token.
 * - The value of config.jw_key.alg, if not "none" must also match the token
 * - The token MUST have a signature block.
 * - The key MUST be usable for the operation, either via the "use" attribute
 *   being "sig" or the "key_ops" attribute have the "verify" bit set.
 * - The defined signature MUST pass.
 *
 * If you want to decode an unsigned JWT, these MUST be true:
 * - The config.alg and jwt.alg MUST be "none"
 * - The config.jw_key MUST be NULL
 * - The signature block in the token MUST be empty
 *
 * If you want to inspect a signed token, you should use jwt_verify_wcb() and
 * use a callback function.
 *
 * @param token Pointer to a nil terminated JWT string
 * @param config Pointer to a config structure to define how to verify the
 *  token. This can be NULL, in which case the token is simply decoded.
 * @return Pointer to a jwt_t object or NULL. Generally a NULL is unlikely. The
 *  object should be checked with jwt_error() to check for errors.
 */
JWT_EXPORT
jwt_t *jwt_verify(const char *token, jwt_config_t *config);

/**
 * @brief Decode and verify a JWT, with user callback
 *
 * This operates the same as @ref jwt_verify, with the addition of calling
 * a user defined callback function between the decode and verification step.
 * This allows the user to perform some extra verification, and even provide a
 * key after decoding (e.g. to match a ``"kid"``).
 *
 * The callback function is performed after initial parsing of the head and
 * body parts of the token, but before verification. The callback can then
 * inspect portions of the JWT, update the config (e.g. to set an alg or a
 * jw_key).
 *
 * The callback function can return non-zero to stop processing immediately.
 * If the callback function returns zero, it does not mean that further
 * verification will succeed. All aspects of jwt_verify() must still be
 * followed.
 *
 * @param token Pointer to a nil terminated JWT string
 * @param config Pointer to a config structure to define how to verify the
 *  token. This can be NULL, in which case the token is simply decoded.
 * @param cb Pointer to a callback
 * @return Pointer to a jwt_t object or NULL. Generally a NULL is unlikely. The
 *  object should be checked with jwt_error() to check for errors.
 */
JWT_EXPORT
jwt_t *jwt_verify_wcb(const char *token, jwt_config_t *config,
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
const char *jwt_get_grant(const jwt_t *jwt, const char *grant);

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
long jwt_get_grant_int(const jwt_t *jwt, const char *grant);

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
int jwt_get_grant_bool(const jwt_t *jwt, const char *grant);

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
char *jwt_get_grants_json(const jwt_t *jwt, const char *grant);

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
const char *jwt_get_header(const jwt_t *jwt, const char *header);

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
long jwt_get_header_int(const jwt_t *jwt, const char *header);

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
int jwt_get_header_bool(const jwt_t *jwt, const char *header);

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
char *jwt_get_headers_json(const jwt_t *jwt, const char *header);

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
 *  or @ref JWT_ALG_INVAL if no  matches were found.
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
 * @defgroup jwks_core_grp JSON Web Key Management
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
 * @brief Create or add to a keyring of JSON Web Keys
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
 *   or array of "keys". If NULL is passed, an empty jwk_set_t is
 *   created. Must be null terminated.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 */
JWT_EXPORT
jwk_set_t *jwks_load(jwk_set_t *jwk_set, const char *jwk_json_str);

/**
 * @brief Create a new JWKS object from a string of known lenght
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
 */
JWT_EXPORT
jwk_set_t *jwks_load_strb(jwk_set_t *jwk_set, const char *jwk_json_str,
			    const size_t len);

/**
 * @brief Create a new JWKS object from a file
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
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromfile(jwk_set_t *jwk_set, const char *file_name);

/**
 * @brief Create a new JWKS object from a FILE pointer
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
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromfp(jwk_set_t *jwk_set, FILE *input);

/**
 * @brief Wrapper around jwks_load() that explicitly creates a new keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create(const char *jwk_json_str);

/**
 * @brief Wrapper around jwks_load_strb() that explicitly creates a new keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create_strb(const char *jwk_json_str, const size_t len);

/**
 * @brief Wrapper around jwks_load_fromfile() that explicitly creates a new
 *  keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromfile(const char *file_name);

/**
 * @brief Wrapper around jwks_load_fromfp() that explicitly creates a new
 *  keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromfp(FILE *input);

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
 */
JWT_EXPORT
int jwks_error(const jwk_set_t *jwk_set);

/**
 * @brief Check if there is an error within the jwk_set and any of
 * the jwk_item_t in the set.
 *
 * @param jwk_set An existing jwk_set_t
 * @return 0 if no error exists, 1 if any exists.
 */
JWT_EXPORT
int jwks_error_any(jwk_set_t *jwk_set);

/**
 * @brief Retrieve an error message from a jwk_set. Note, a zero
 * length string is valid if jwos_error() returns non-zero.
 *
 * @param jwk_set An existing jwk_set_t
 * @return A string message. The string may be empty.
 */
JWT_EXPORT
const char *jwks_error_msg(const jwk_set_t *jwk_set);

/**
 * @brief Clear an error condition in a jwk_set
 *
 * @param jwk_set An existing jwk_set_t
 */
JWT_EXPORT
void jwks_error_clear(jwk_set_t *jwk_set);

/**
 * Free all memory associated with a jwt_set_t, including any jwk_item_t in
 * the set.
 *
 * @param jwk_set An existing jwk_set_t
 */
JWT_EXPORT
void jwks_free(jwk_set_t *jwk_set);

#if defined(__GNUC__) || defined(__clang__)
/**
 * @brief Helper function to free a JWK Set and set the pointer to NULL
 *
 * This is mainly to use with the jwt_set_auto_t type.
 *
 * @param Pointer to a pointer for a jwt_set_t object
 */
static inline void jwks_freep(jwk_set_t **jwks) {
	if (jwks) {
		jwks_free(*jwks);
		*jwks = NULL;
	}
}
#define jwk_set_auto_t jwk_set_t __attribute__((cleanup(jwks_freep)))
#endif

/**
 * @}
 * @noop jwks_core_grp
 */

/**
 * @defgroup jwks_item_grp JSON Web Key Usage
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
 */
JWT_EXPORT
const jwk_item_t *jwks_item_get(const jwk_set_t *jwk_set, size_t index);

/**
 * @brief Whether this key is private (or public)
 *
 * @param item A JWK Item
 * @return 1 for true, 0 for false
 */
JWT_EXPORT
int jwks_item_is_private(const jwk_item_t *item);

/**
 * @brief Check the error condition for this JWK
 *
 * @param item A JWK Item
 * @return 1 for true, 0 for false
 */
JWT_EXPORT
int jwks_item_error(const jwk_item_t *item);

/**
 * @brief Check the error message for a JWK Item
 *
 * @param item A JWK Item
 * @return A string message. Empty string if no error.
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
 */
JWT_EXPORT
const char *jwks_item_curve(const jwk_item_t *item);

/**
 * @brief A kid (Key ID) for this JWK
 *
 * @param item A JWK Item
 * @return A string of the kid if one exists. NULL otherwise.
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
 */
JWT_EXPORT
jwt_alg_t jwks_item_alg(const jwk_item_t *item);

/**
 * @brief The Key Type of this JWK
 *
 * @param item A JWK Item
 * @return A jwk_key_type_t type for this key
 */
JWT_EXPORT
jwk_key_type_t jwks_item_kty(const jwk_item_t *item);

/**
 * @brief The ``"use"`` field for this JWK
 *
 * @param item A JWK Item
 * @return A jwk_pub_key_use_t type for this key
 */
JWT_EXPORT
jwk_pub_key_use_t jwks_item_use(const jwk_item_t *item);

/**
 * @brief The ``"key_ops"`` field for this JWK
 *
 * @param item A JWK Item
 * @return A jwk_key_op_t type for this key which represents all of the
 *   ``"key_ops"`` supported as a bit field.
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
 */
JWT_EXPORT
const char *jwks_item_pem(const jwk_item_t *item);

/**
 * @brief The number of bits in this JWK
 *
 * This is relevant to the key type (kty). E.g. an RSA key would have atleast
 * 2048 bits, and an EC key would be 256, 384, or 521 bits, etc.
 *
 * @param item A JWK Item
 * @return The number of bits for the key
 */
JWT_EXPORT
int jwks_item_key_bits(const jwk_item_t *item);

/**
 * Free all memory associated with the nth jwk_item_t in a jwk_set
 *
 * @param jwk_set A JWKS object
 * @param index the position of the item in the index
 * @return 0 if no item was was deleted (found), 1 if it was
 */
JWT_EXPORT
int jwks_item_free(jwk_set_t *jwk_set, size_t index);

/**
 * Free all memory associated with all @ref jwk_item_t in a @ref jwk_set_t.
 * The jwk_set_t becomes an empty set.
 *
 * @param jwk_set A JWKS object
 * @return The number of items deleted
 */
JWT_EXPORT
int jwks_item_free_all(jwk_set_t *jwk_set);

/**
 * @}
 * @noop jwks_item_grp
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
