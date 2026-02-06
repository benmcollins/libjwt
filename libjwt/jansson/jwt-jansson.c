/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Jansson JSON backend for libjwt.
 *
 * Implements the jwt_json_* abstraction using jansson.
 */

#include <jansson.h>
#include "jwt-json-ops.h"

#include <string.h>

/* ================================================================
 * Memory allocator override
 * ================================================================ */

void jwt_json_set_alloc(void *(*alloc_func)(size_t),
			void (*free_func)(void *))
{
	json_set_alloc_funcs(alloc_func, free_func);
}

/* ================================================================
 * Internal helpers: cast between opaque jwt_json_t and json_t
 * ================================================================ */

static inline json_t *to_json(const jwt_json_t *j)
{
	return (json_t *)j;
}

static inline jwt_json_t *from_json(json_t *j)
{
	return (jwt_json_t *)j;
}

/* ================================================================
 * Internal: translate jwt_json flags to native jansson flags
 * ================================================================ */

static size_t encode_flags(size_t flags)
{
	size_t jflags = 0;

	int indent = flags & 0x1F;
	if (indent > 0)
		jflags |= JSON_INDENT(indent);
	if (flags & JWT_JSON_COMPACT)
		jflags |= JSON_COMPACT;
	if (flags & JWT_JSON_SORT_KEYS)
		jflags |= JSON_SORT_KEYS;

	return jflags;
}

static size_t decode_flags(size_t flags)
{
	size_t jflags = 0;

	if (flags & JWT_JSON_REJECT_DUPLICATES)
		jflags |= JSON_REJECT_DUPLICATES;
	if (flags & JWT_JSON_DECODE_ANY)
		jflags |= JSON_DECODE_ANY;

	return jflags;
}

/* ================================================================
 * Internal: map jansson json_error_t to jwt_json_error_t
 * ================================================================ */

static void map_error(jwt_json_error_t *dst, const json_error_t *src)
{
	if (!dst)
		return;

	memset(dst, 0, sizeof(*dst));

	if (src) {
		snprintf(dst->text, JWT_JSON_ERROR_TEXT_LENGTH,
			 "%s", src->text);
		snprintf(dst->source, JWT_JSON_ERROR_SOURCE_LENGTH,
			 "%s", src->source);
		dst->line = src->line;
		dst->column = src->column;
		dst->position = src->position;
	}
}

/* ================================================================
 * Reference counting
 * ================================================================ */

void jwt_json_releasep(jwt_json_t **json)
{
	if (json) {
		json_t *j = to_json(*json);
		json_decref(j);
		*json = NULL;
	}
}

void jwt_json_release(jwt_json_t *json)
{
	json_decref(to_json(json));
}

/* ================================================================
 * Object creation
 * ================================================================ */

jwt_json_t *jwt_json_create(void)
{
	return from_json(json_object());
}

jwt_json_t *jwt_json_create_arr(void)
{
	return from_json(json_array());
}

jwt_json_t *jwt_json_create_str(const char *value)
{
	return from_json(json_string(value));
}

jwt_json_t *jwt_json_create_int(jwt_json_int_t value)
{
	return from_json(json_integer(value));
}

jwt_json_t *jwt_json_create_bool(int value)
{
	return from_json(json_boolean(value));
}

/* ================================================================
 * Object operations
 * ================================================================ */

jwt_json_t *jwt_json_obj_get(const jwt_json_t *object, const char *key)
{
	return from_json(json_object_get(to_json(object), key));
}

int jwt_json_obj_set(jwt_json_t *object, const char *key, jwt_json_t *value)
{
	return json_object_set_new(to_json(object), key, to_json(value));
}

int jwt_json_obj_del(jwt_json_t *object, const char *key)
{
	return json_object_del(to_json(object), key);
}

int jwt_json_obj_clear(jwt_json_t *object)
{
	return json_object_clear(to_json(object));
}

int jwt_json_obj_merge(jwt_json_t *object, jwt_json_t *other)
{
	return json_object_update(to_json(object), to_json(other));
}

int jwt_json_obj_merge_new(jwt_json_t *object, jwt_json_t *other)
{
	return json_object_update_missing(to_json(object), to_json(other));
}

/* ================================================================
 * Array operations
 * ================================================================ */

size_t jwt_json_arr_size(const jwt_json_t *array)
{
	return json_array_size(to_json(array));
}

jwt_json_t *jwt_json_arr_get(const jwt_json_t *array, size_t index)
{
	return from_json(json_array_get(to_json(array), index));
}

int jwt_json_arr_append(jwt_json_t *array, jwt_json_t *value)
{
	return json_array_append_new(to_json(array), to_json(value));
}

/* ================================================================
 * Type checking
 * ================================================================ */

int jwt_json_is_array(const jwt_json_t *json)
{
	return json_is_array(to_json(json));
}

int jwt_json_is_string(const jwt_json_t *json)
{
	return json_is_string(to_json(json));
}

int jwt_json_is_int(const jwt_json_t *json)
{
	return json_is_integer(to_json(json));
}

int jwt_json_is_bool(const jwt_json_t *json)
{
	return json_is_boolean(to_json(json));
}

int jwt_json_is_true(const jwt_json_t *json)
{
	return json_is_true(to_json(json));
}

/* ================================================================
 * Value extraction
 * ================================================================ */

const char *jwt_json_str_val(const jwt_json_t *json)
{
	return json_string_value(to_json(json));
}

jwt_json_int_t jwt_json_int_val(const jwt_json_t *json)
{
	return json_integer_value(to_json(json));
}

/* ================================================================
 * Deep copy
 * ================================================================ */

jwt_json_t *jwt_json_clone(const jwt_json_t *value)
{
	return from_json(json_deep_copy(to_json(value)));
}

/* ================================================================
 * Serialization / Parsing
 * ================================================================ */

char *jwt_json_serialize(const jwt_json_t *json, size_t flags)
{
	return json_dumps(to_json(json), encode_flags(flags));
}

jwt_json_t *jwt_json_parse(const char *input, size_t flags,
			   jwt_json_error_t *error)
{
	json_error_t jerr;
	json_t *obj = json_loads(input, decode_flags(flags), &jerr);

	if (!obj && error)
		map_error(error, &jerr);

	return from_json(obj);
}

jwt_json_t *jwt_json_parse_buf(const char *buffer, size_t buflen,
			       size_t flags, jwt_json_error_t *error)
{
	json_error_t jerr;
	json_t *obj = json_loadb(buffer, buflen, decode_flags(flags), &jerr);

	if (!obj && error)
		map_error(error, &jerr);

	return from_json(obj);
}

jwt_json_t *jwt_json_parse_file(const char *path, size_t flags,
				jwt_json_error_t *error)
{
	json_error_t jerr;
	json_t *obj = json_load_file(path, decode_flags(flags), &jerr);

	if (!obj && error)
		map_error(error, &jerr);

	return from_json(obj);
}

jwt_json_t *jwt_json_parse_fp(FILE *input, size_t flags,
			      jwt_json_error_t *error)
{
	json_error_t jerr;
	json_t *obj = json_loadf(input, decode_flags(flags), &jerr);

	if (!obj && error)
		map_error(error, &jerr);

	return from_json(obj);
}
