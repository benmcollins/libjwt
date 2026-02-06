/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * JSON backend abstraction for libjwt.
 *
 * Common interface header for all JSON backends (jansson, json-c).
 * Each backend provides a .c file implementing these functions.
 */

#ifndef JWT_JSON_OPS_H
#define JWT_JSON_OPS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ================================================================
 * Types
 * ================================================================ */

/** Opaque JSON type - backends cast internally to the real lib struct */
typedef struct jwt_json_s jwt_json_t;

typedef int64_t jwt_json_int_t;

#define JWT_JSON_ERROR_TEXT_LENGTH	160
#define JWT_JSON_ERROR_SOURCE_LENGTH	80

typedef struct {
	char text[JWT_JSON_ERROR_TEXT_LENGTH];
	char source[JWT_JSON_ERROR_SOURCE_LENGTH];
	int line;
	int column;
	size_t position;
} jwt_json_error_t;

/* ================================================================
 * Flags
 * ================================================================ */

/* Encoding */
#define JWT_JSON_INDENT(n)		((n) & 0x1F)
#define JWT_JSON_COMPACT		0x20
#define JWT_JSON_SORT_KEYS		0x80

/* Decoding */
#define JWT_JSON_REJECT_DUPLICATES	0x01
#define JWT_JSON_DECODE_ANY		0x08

/* ================================================================
 * Memory allocator override
 * ================================================================ */

void jwt_json_set_alloc(void *(*alloc_func)(size_t),
			void (*free_func)(void *));

/* ================================================================
 * Reference counting & auto cleanup
 * ================================================================ */

void jwt_json_releasep(jwt_json_t **json);
#define jwt_json_auto_t jwt_json_t __attribute__((cleanup(jwt_json_releasep)))

jwt_json_t *jwt_json_retain(jwt_json_t *json);
void jwt_json_release(jwt_json_t *json);

/* ================================================================
 * Object creation
 * ================================================================ */

jwt_json_t *jwt_json_create(void);
jwt_json_t *jwt_json_create_arr(void);
jwt_json_t *jwt_json_create_str(const char *value);
jwt_json_t *jwt_json_create_int(jwt_json_int_t value);
jwt_json_t *jwt_json_create_bool(int value);

/* ================================================================
 * Object operations
 * ================================================================ */

jwt_json_t *jwt_json_obj_get(const jwt_json_t *object, const char *key);
int jwt_json_obj_set(jwt_json_t *object, const char *key, jwt_json_t *value);
int jwt_json_obj_del(jwt_json_t *object, const char *key);
int jwt_json_obj_clear(jwt_json_t *object);
int jwt_json_obj_merge(jwt_json_t *object, jwt_json_t *other);
int jwt_json_obj_merge_new(jwt_json_t *object, jwt_json_t *other);

/* ================================================================
 * Array operations
 * ================================================================ */

size_t jwt_json_arr_size(const jwt_json_t *array);
jwt_json_t *jwt_json_arr_get(const jwt_json_t *array, size_t index);
int jwt_json_arr_append(jwt_json_t *array, jwt_json_t *value);

#define jwt_json_arr_foreach(array, index, value)		\
	for ((index) = 0;					\
	     (index) < jwt_json_arr_size(array) &&		\
	     ((value) = jwt_json_arr_get((array), (index)));	\
	     (index)++)

/* ================================================================
 * Type checking
 * ================================================================ */

int jwt_json_is_object(const jwt_json_t *json);
int jwt_json_is_array(const jwt_json_t *json);
int jwt_json_is_string(const jwt_json_t *json);
int jwt_json_is_int(const jwt_json_t *json);
int jwt_json_is_bool(const jwt_json_t *json);
int jwt_json_is_true(const jwt_json_t *json);

/* ================================================================
 * Value extraction
 * ================================================================ */

const char *jwt_json_str_val(const jwt_json_t *json);
jwt_json_int_t jwt_json_int_val(const jwt_json_t *json);

/* ================================================================
 * Deep copy
 * ================================================================ */

jwt_json_t *jwt_json_clone(const jwt_json_t *value);

/* ================================================================
 * Serialization / Parsing
 * ================================================================ */

char *jwt_json_serialize(const jwt_json_t *json, size_t flags);

jwt_json_t *jwt_json_parse(const char *input, size_t flags,
			   jwt_json_error_t *error);
jwt_json_t *jwt_json_parse_buf(const char *buffer, size_t buflen,
			       size_t flags, jwt_json_error_t *error);
jwt_json_t *jwt_json_parse_file(const char *path, size_t flags,
				jwt_json_error_t *error);
jwt_json_t *jwt_json_parse_fp(FILE *input, size_t flags,
			      jwt_json_error_t *error);

#endif /* JWT_JSON_OPS_H */
