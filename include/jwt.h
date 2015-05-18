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

/* Allocates a JWT object for later use. */
int jwt_new(jwt_t **jwt);

/* Free's a JWT object and any memory it is using. */
void jwt_free(jwt_t *jwt);

/* Return a value for a grant. Returns NULL if it doesn't exist. */
const char *jwt_get_grant(jwt_t *jwt, const char *grant);

/* Add a new grant and value to the JWT. */
int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val);

/* Delete a grant from the JWT. */
int jwt_del_grant(jwt_t *jwt, const char *grant);

/* Dump the contents of the grants to FILE* */
int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty);

/* Encode the grants to FILE* with b64 encoding. */
int jwt_encode_fp(jwt_t *jwt, FILE *fp);

/* Set the algorithm for the JWT. */
int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg);

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
