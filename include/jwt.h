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

/** @ingroup jwt_object_grp
 * @brief Opaque JWT object
 *
 * Used in callbacks when generating or verifying a JWT
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
 */
typedef struct jwk_set jwk_set_t;

/** @ingroup jwt_alg_grp
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

/** @ingroup jwks_item_grp
 * @brief JWK Key Types
 *
 * Corresponds to the ``"kty"`` attribute of the JWK.
 *
 * @rfc{7517,4.1}
 * @rfc{7518,6.1}
 */
typedef enum {
	JWK_KEY_TYPE_NONE = 0,		/**< Unused on valid keys */
	JWK_KEY_TYPE_EC,		/**< Elliptic Curve keys */
	JWK_KEY_TYPE_RSA,		/**< RSA keys (RSA and RSA-PSS) */
	JWK_KEY_TYPE_OKP,		/**< Octet Key Pair (e.g. EdDSA) */
	JWK_KEY_TYPE_OCT,		/**< Octet sequence (e.g. HS256) */
} jwk_key_type_t;

/** @ingroup jwks_item_grp
 * @brief Usage types for JWK public keys
 *
 * Corresponds to the ``"use"`` attribute in a JWK the represents a public key.
 *
 * @rfc{7517,4.2}
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
 */
typedef struct {
	jwt_value_type_t type;
	const char *name;
	union {
		long int_val;
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
 */
typedef struct jwk_item jwk_item_t;

/** @ingroup jwt_memory_grp
 * @brief Prototype for malloc(3)
 */
typedef void *(*jwt_malloc_t)(size_t);

/** @ingroup jwt_memory_grp
 * @brief Prototype for free(3)
 */
typedef void (*jwt_free_t)(void *);

/** @ingroup jwt_alg_grp
 * Get the jwt_alg_t set for this JWT object.
 *
 * Returns the jwt_alg_t type for this JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @returns Returns a jwt_alg_t type for this object.
 */
JWT_EXPORT
jwt_alg_t jwt_get_alg(const jwt_t *jwt);

/** @ingroup jwt_object_grp
 * @brief Structure used to pass state with a user callback
 */
typedef struct {
	const jwk_item_t *key;	/**< A JWK to use for key	*/
	jwt_alg_t alg;		/**< For algorithm matching	*/
	void *ctx;		/**< User controlled context	*/
} jwt_config_t;

/** @ingroup jwt_object_grp
 * @brief General callback for generation and verification of JWT
 */
typedef int (*jwt_callback_t)(jwt_t *, jwt_config_t *);

/** @ingroup jwt_claims_helpers_grp
 * @brief WFC defined claims
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
 * @{
 */

/**
 * @defgroup jwt_builder_grp Builder
 *
 * Creating a JWT token involves several steps. First is creating a
 * jwt_builder_t object, which can be thought of as a JWT factory. Once
 * configured, you can use it to create tokens with pre-defined claims.
 * @{
 */

/**
 * @brief Opaque Builder Object
 */
typedef struct jwt_builder jwt_builder_t;

/**
 * @brief Function to create a new builder instance
 *
 * @return Pointer to a builder object on success, NULL on failure
 */
JWT_EXPORT
jwt_builder_t *jwt_builder_new(void);

/**
 * @brief Frees a previously created builder object
 *
 * @param builder Pointer to a builder object
 */
JWT_EXPORT
void jwt_builder_free(jwt_builder_t *builder);

#if defined(__GNUC__) || defined(__clang__)
/**
 * @brief Helper function to free a builder and set the pointer to NULL
 *
 * This is mainly to use with the jwt_builder_auto_t type.
 *
 * @param Pointer to a pointer for a jwt_builder_t object
 */
static inline void jwt_builder_freep(jwt_builder_t **builder) {
	if (builder) {
		jwt_builder_free(*builder);
		*builder = NULL;
	}
}
#define jwt_builder_auto_t jwt_builder_t \
	__attribute__((cleanup(jwt_builder_freep)))
#endif

/**
 * @brief Checks error state of builder object
 *
 * @param builder Pointer to a builder object
 * @return 0 if no errors exist, non-zero otherwise
 */
JWT_EXPORT
int jwt_builder_error(const jwt_builder_t *builder);

/**
 * @brief Get the error message contained in a builder object
 *
 * @param builder Pointer to a builder object
 * @return Pointer to a string with the error message. Can be an empty string
 *  if there is no error. Never returns NULL.
 */
JWT_EXPORT
const char *jwt_builder_error_msg(const jwt_builder_t *builder);

/**
 * @brief Clear error state in a builder object
 *
 * @param builder Pointer to a builder object
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
 */
JWT_EXPORT
int jwt_builder_setkey(jwt_builder_t *builder, const jwt_alg_t alg,
		       const jwk_item_t *key);

/**
 * @brief Set IssuedAt usage on builder
 *
 * By default, the builder will set the ``iat`` claim to all tokens. You can
 * enable or disable this using this function.
 *
 * @param builder Pointer to a builder object
 * @param enable 0 to disable, any other value to enable
 * @return Previous value (0 or 1), or -1 on error
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
 */
JWT_EXPORT
int jwt_builder_setcb(jwt_builder_t *builder, jwt_callback_t cb, void *ctx);

/**
 * @brief Retrieve the callback context that was previously set
 *
 * This is useful for accessing the context that was previously passed in the
 * setcb function.
 *
 * @param builder Pointer to a builder object
 * @return Pointer to the context or NULL
 */
JWT_EXPORT
void *jwt_builder_getctx(jwt_builder_t *builder);

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
 * Validating a JWT involves decoding the Base64url parts of the JWT then
 * verifying claims and the signature hash. The checker object allows you to
 * configure how you want to perform these steps so you can easily process
 * tokens with one simple call.
 * @{
 */

/**
 * @brief Opaque Checker object
 */
typedef struct jwt_checker jwt_checker_t;

/**
 * @brief Function to create a new checker instance
 *
 * @return Pointer to a checker object on success, NULL on failure
 */
JWT_EXPORT
jwt_checker_t *jwt_checker_new(void);

/**
 * @brief Frees a previously created checker object
 *
 * @param checker Pointer to a checker object
 */
JWT_EXPORT
void jwt_checker_free(jwt_checker_t *checker);

#if defined(__GNUC__) || defined(__clang__)
/**
 * @brief Helper function to free a checker and set the pointer to NULL
 *
 * This is mainly to use with the jwt checker_auto_t type. Example usage:
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
 * @param Pointer to a pointer for a jwt checker_t object
 */
static inline void jwt_checker_freep(jwt_checker_t **checker) {
        if (checker) {
                jwt_checker_free(*checker);
                *checker = NULL;
        }
}
#define jwt_checker_auto_t jwt_checker_t \
        __attribute__((cleanup(jwt_checker_freep)))
#endif

/**
 * @brief Checks error state of checker object
 *
 * @param checker Pointer to a checker object
 * @return 0 if no errors exist, non-zero otherwise
 */
JWT_EXPORT
int jwt_checker_error(const jwt_checker_t *checker);

/**
 * @brief Get the error message contained in a checker object
 *
 * @param checker Pointer to a checker object
 * @return Pointer to a string with the error message. Can be an empty string
 *  if there is no error. Never returns NULL.
 */
JWT_EXPORT
const char *jwt_checker_error_msg(const jwt_checker_t *checker);

/**
 * @brief Clear error state in a checker object
 *
 * @param checker Pointer to a checker object
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
 */
JWT_EXPORT
int jwt_checker_setkey(jwt_checker_t *checker, const jwt_alg_t alg, const
		       jwk_item_t *key);

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
 */
JWT_EXPORT
int jwt_checker_setcb(jwt_checker_t *checker, jwt_callback_t cb, void *ctx);

/**
 * @brief Retrieve the callback context that was previously set
 *
 * This is useful for accessing the context that was previously passed in the
 * setcb function.
 *
 * @param checker Pointer to a checker object
 * @return Pointer to the context or NULL
 */
JWT_EXPORT
void *jwt_checker_getctx(jwt_checker_t *checker);

/**
 * @brief Verify a token
 *
 * @note If you set a callback for this checker, this is when it will be called.
 *
 * @param checker Pointer to a checker object
 * @param token A string containing a token to be verified
 * @return 0 on success, non-zero otherwise with error set in the checker
 */
JWT_EXPORT
int jwt_checker_verify(jwt_checker_t *checker, const char *token);

/**
 * @}
 * @noop jwt_checker_grp
 */

/**
 * @defgroup jwt_claims_grp Claims and Headers
 *
 * Working with claims and header elements across checker and builder
 * objects is similar, but the usage for it is not.
 *
 * @{
 */

/**
 * @defgroup jwt_claims_helpers_grp Utility Functions
 * @{
 */

/**
 * @defgroup jwt_helpers_get_grp Getters
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
 * Claim   | Type      | Comparison for Validation
 * ------- | --------- | -----------------------------
 * ``exp`` | Timestamp | ``exp`` > (now + leeway)
 * ``nbf`` | Timestamp | ``nbf`` <= (now - leeway)
 * ``iss`` | String    | !strcmp(``iss``, ``userval``)
 * ``aud`` | String    | !strcmp(``aud``, ``userval``)
 * ``sub`` | String    | !strcmp(``sub``, ``userval``)
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
 */
JWT_EXPORT
jwt_value_error_t jwt_claim_get(jwt_t *jwt, jwt_value_t *value);

/**
 * @brief Delete a value from the claims of a JWT
 *
 * @param jwt Pointer to a jwt_t token, previously created with jwt_create()
 * @param claim The name of the claim to delete, or NULL to clear all claims
 * @return A jwt_value_error_t value, JWT_VALUE_ERR_NONE being success.
 */
JWT_EXPORT
jwt_value_error_t jwt_claim_del(jwt_t *jwt, const char *claim);

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
 * @defgroup jwks_grp JSON Web Keys
 * @{
 */

/**
 * @defgroup jwks_core_grp JWK Management
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
 *   or array of "keys". If NULL is passed, an empty jwk_set_t is
 *   created. Must be null terminated.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
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
 * @param verify Set to 1 to verify the Host, 2 to verify Host and Peer.
 *   2 is recommended unless you really need to disable with 0.
 * @return A valid jwt_set_t on success. On failure, either NULL
 *   or a jwt_set_t with error set. NULL generally means ENOMEM.
 */
JWT_EXPORT
jwk_set_t *jwks_load_fromurl(jwk_set_t *jwk_set, const char *url, int verify);

/**
 * @brief Wrapper around jwks_load() that explicitly creates a new keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create(const char *jwk_json_str);

/**
 * @brief Wrapper around jwks_load_strn() that explicitly creates a new keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create_strn(const char *jwk_json_str, const size_t len);

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
 * @brief Wrapper around jwks_load_fromurl() that explicitly creates a new
 *  keyring
 */
JWT_EXPORT
jwk_set_t *jwks_create_fromurl(const char *url, int verify);

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
 * @return 0 if no error exists, or the number of errors in the set
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
 * @brief Find a jwk_item_t with a specific kid (Key ID)
 *
 * LibJWT does not ensure that kid's are unique in a given keyring, so care
 * must be taken. This will return the first match.
 *
 * @param jwk_set An existing jwk_set_t
 * @param kid String representing a ``kid`` to find
 * @return A jwk_item_t object or NULL if none found
 */
JWT_EXPORT
jwk_item_t *jwks_find_bykid(jwk_set_t *jwk_set, const char *kid);

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
 * @brief Retrieve binary octet data of a key
 *
 * Only valid for JWT_KEY_TYPE_OCT.
 *
 * @param item A JWK Item
 * @param buf Pointer to a pointer buffer
 * @param len Pointer to a length
 * @return 0 on success. @p buf will point to data of @c len length. Non-zero on
 *  error.
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
 */
JWT_EXPORT
int jwks_item_key_bits(const jwk_item_t *item);

/**
 * @brief Free remove and free the nth jwk_item_t in a jwk_set
 *
 * @param jwk_set Pointer to a JWKS object
 * @param index the position of the item in the index
 * @return 0 if no item was was deleted (found), 1 if it was
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
 */
JWT_EXPORT
int jwks_item_free_bad(jwk_set_t *jwk_set);

/**
 * @brief Return the number of keys in a jwk_set_t
 *
 * @param jwk_set Pointer to a JWKS object
 * @return The number of items in the set
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
 * @{
 */

/**
 * @defgroup jwt_memory_grp Memory Handlers
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
  */
JWT_EXPORT
int jwt_set_alloc(jwt_malloc_t pmalloc, jwt_free_t pfree);

/**
 * Get functions used for allocating and freeing memory.
 *
 * @param pmalloc Pointer to malloc function output variable, or NULL
 * @param pfree Pointer to free function output variable, or NULL
 */
JWT_EXPORT
void jwt_get_alloc(jwt_malloc_t *pmalloc, jwt_free_t *pfree);

 /**
  * @}
  * @noop jwt_memory_grp
  */

/**
 * @defgroup jwt_crypto_grp Cryptographic Ops
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
 * @return 0 on success, 1 for error
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
 * @noop jwt_advanced_grp
 */

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
