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

#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jwt jwt_t;

typedef enum jwt_alg {
	JWT_ALG_NONE = 0,
	JWT_ALG_HS256
} jwt_alg_t;

/**
 * Allocate a new, empty, JWT object.
 *
 * This is generally used to create a new object for a JWT. After you
 * have finished with the object, use jwt_free() to clean up the
 * memory used by it.
 *
 * @param jwt Pointer to a JWT object pointer. Will be allocated on
 *            success.
 * @return 0 on success, valid errno otherwise.
 */
int jwt_new(jwt_t **jwt);

/**
 * Free a JWT object and any other resources it is using.
 *
 * After calling, the JWT object referenced will no longer be valid and
 * it's memory will be freed.
 *
 * @param jwt Pointer to a JWT object previously created with jwt_new()
 *            or jwt_decode().
 */
void jwt_free(jwt_t *jwt);

/**
 * Return the value of a grant.
 *
 * Returns the string value for a grant (e.g. "iss"). If it does not exit,
 * NULL will be returned.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *        for.
 * @return Returns a string for the value, or NULL when not found.
 */
const char *jwt_get_grant(jwt_t *jwt, const char *grant);

/**
 * Add a new grant to this JWT object.
 *
 * Creates a new grant for this object. The string for grant and val
 * are copied internally, so do not require that the pointer or string
 * remain valid for the lifetime of this object.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *        for.
 * @param val String containing the value to be saved or grant. Can be
 *            an empty string, but cannot be NULL.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val);

/**
 * Delete a grant from this JWT object.
 *
 * Deletes the named grant from this object. It is not an error if there
 * is no grant matching the passed value.
 *
 * @param jwt Pointer to a JWT object.
 * @param grant String containing the name of the grant to return a value
 *        for.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_del_grant(jwt_t *jwt, const char *grant);

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
 * @param pretty Enabled better visual formatting of out. Generally only
 *               used for debugging.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty);

/**
 * Fully encode a JWT object and write it to FILE.
 *
 * This will create and write the complete JWT object to FILE. All parts
 * will be Bas64 encoded and signatures or encryption will be applied if
 * the algorithm specified requires it.
 *
 * @param jwt Pointer to a JWT object.
 * @param fp Valid FILE pointer to write data to.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_encode_fp(jwt_t *jwt, FILE *fp);

/**
 * Set an algorithm from jwt_alg_t for this JWT object.
 *
 * Specifies an algorithm for a JWT object. If JWT_ALG_NONE is used, then
 * key must be NULL and len must be 0. All other algorithms must have a
 * valid pointer to key data of a length specific to the algorithm
 * specified (e.g., HS256 requires 32 Bytes of key).
 *
 * @param jwt Pointer to a JWT object.
 * @param alg A valid jwt_alg_t specififier.
 * @param key The key data to use for the algorithm.
 * @param len The length of the key data.
 * @return Returns 0 on success, valid errno otherwise.
 */
int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, unsigned char *key, int len);

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
