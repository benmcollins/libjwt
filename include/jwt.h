/* Copyright (C) 2015 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/**
 * @file jwt.h
 * @brief JWT C Library
 */

#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque JWT object. */
typedef struct jwt jwt_t;

/** JWT algorithm types. */
typedef enum jwt_alg {
	JWT_ALG_NONE = 0,
	JWT_ALG_HS256,
	JWT_ALG_HS384,
	JWT_ALG_HS512
} jwt_alg_t;

/**
 * @defgroup jwt_new JWT Object Creation
 * Functions used to create and destroy JWT objects.
 *
 * Generally, one would use the jwt_new() function to create an object
 * from scratch and jwt_decode() to create and verify and object from an
 * existing token.
 * @{
 */

/**
 * Allocate a new, empty, JWT object.
 *
 * This is used to create a new object for a JWT. After you have finished
 * with the object, use jwt_free() to clean up the memory used by it.
 *
 * @param jwt Pointer to a JWT object pointer. Will be allocated on
 *     success.
 * @return 0 on success, valid errno otherwise.
 */
int jwt_new(jwt_t **jwt);

/**
 * Verify an existing JWT and allocate a new JWT object from it.
 *
 * Decodes a JWT string and verifies the signature (if one is supplied).
 * If no signature is used (JWS, alg="none") or key is NULL, then no
 * validation is done other than formatting. It is not suggested to use
 * this on a string that has a signature without passing the key to
 * verify it. If the JWT is encrypted and no key is supplied, an error
 * is returned.
 *
 * @param jwt Pointer to a JWT object pointer. Will be allocated on
 *     success.
 * @param token Pointer to a valid JWT string, nul terminated.
 * @param key Pointer to the key for validating the JWT signature or for
 *     decrypting the token or NULL if no validation is to be performed.
 * @param key_len The length of the above key. Must match the algorithm
 *     (e.g. 32 for HS256) and the length of the data in key.
 * @return 0 on success, valid errno otherwise.
 *
 * @remark If a key is supplied, the token must pass sig check or decrypt
 *     for it to be parsed without error. If no key is supplied, then a
 *     non-encrypted token will be parsed without any checks for a valid
 *     signature, however, standard validation of the token is still
 *     performed.
 */
int jwt_decode(jwt_t **jwt, const char *token, const unsigned char *key,
	       int key_len);

/**
 * Free a JWT object and any other resources it is using.
 *
 * After calling, the JWT object referenced will no longer be valid and
 * its memory will be freed.
 *
 * @param jwt Pointer to a JWT object previously created with jwt_new()
 *            or jwt_decode().
 */
void jwt_free(jwt_t *jwt);

/**
 * Duplicate an existing JWT object.
 *
 * Copies all grants and algorithm specific bits to a new JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @return A new object on success, NULL on error with errno set
 *     appropriately.
 */
jwt_t *jwt_dup(jwt_t *jwt);

/** @} */

/**
 * @defgroup jwt_grant JWT Grant Manipulation
 * These functions allow you to add, remove and retrieve grants from a JWT
 * object.
 * @{
 */

/**
 * Return the value of a grant.
 *
 * Returns the string value for a grant (e.g. "iss"). If it does not exit,
 * NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *     for.
 * @return Returns a string for the value, or NULL when not found.
 */
const char *jwt_get_grant(jwt_t *jwt, const char *grant);

/**
 * Add a new grant to this JWT object.
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
 */
int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val);

/**
 * Delete a grant from this JWT object.
 *
 * Deletes the named grant from this object. It is not an error if there
 * is no grant matching the passed name.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to delete.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_del_grant(jwt_t *jwt, const char *grant);

/**
 * Add grants from a JSON encoded object string.
 *
 * Loads grants from an existing JSON encoded object string (the body
 * portion). Overwrites any existing grants. Should be used on a jwt_new()
 * created JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @param json String containing a JSON encoded object of grants.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_add_grants_json(jwt_t *jwt, const char *json);

/** @} */

/**
 * @defgroup jwt_encode JWT Output Functions
 * Functions that enable seeing the plain text or fully encoded version of
 * a JWT object.
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
 * @param jwt Pointer to a JWT object.
 * @param fp Valid FILE pointer to write data to.
 * @param pretty Enables better visual formatting of output. Generally only
 *     used for debugging.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty);

/**
 * Return plain text representation as a string.
 *
 * Similar to jwt_dump_fp() except that a string is returned. The string
 * must be freed by the caller.
 *
 * @param jwt Pointer to a JWT object.
 * @param pretty Enables better visual formatting of output. Generally only
 *     used for debugging.
 * @return A nul terminated string on success, NULL on error with errno
 *     set appropriately.
 */
char *jwt_dump_str(jwt_t *jwt, int pretty);

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
int jwt_encode_fp(jwt_t *jwt, FILE *fp);

/**
 * Fully encode a JWT object and return as a string.
 *
 * Similar to jwt_encode_fp() except that a string is returned. The string
 * must be freed by the caller.
 *
 * @param jwt Pointer to a JWT object.
 * @return A nul terminated string on success, NULL on error with errno
 *     set appropriately.
 */
char *jwt_encode_str(jwt_t *jwt);

/** @} */

/**
 * @defgroup jwt_alg JWT Algorithm Functions
 * Set and check algorithms and algorithm specific values.
 *
 * When working with functions that require a key, the underlying library
 * takes care to scrub memory when the key is no longer used (e.g. when
 * calling jwt_free() or when changing the algorithm, the old key, if it
 * exists, is scrubbed).
 * @{
 */

/**
 * Set an algorithm from jwt_alg_t for this JWT object.
 *
 * Specifies an algorithm for a JWT object. If JWT_ALG_NONE is used, then
 * key must be NULL and len must be 0. All other algorithms must have a
 * valid pointer to key data of a length specific to the algorithm
 * requested (e.g., HS256 requires 32 Bytes of key data).
 *
 * @param jwt Pointer to a JWT object.
 * @param alg A valid jwt_alg_t specifier.
 * @param key The key data to use for the algorithm.
 * @param len The length of the key data.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, unsigned char *key, int len);

/**
 * Get the jwt_alg_t set for this JWT object.
 *
 * Returns the jwt_alg_t type for this JWT object.
 *
 * @param jwt Pointer to a JWT object.
 * @returns Returns a jwt_alg_t type for this object.
 */
jwt_alg_t jwt_get_alg(jwt_t *jwt);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
