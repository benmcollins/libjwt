/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * json-c JSON backend for libjwt.
 *
 * Implements the jwt_json_* abstraction using json-c.
 */

#include <json-c/json.h>
#include "jwt-json-ops.h"

#include <limits.h>
#include <string.h>
#include <stdlib.h>

/* From jwt-memory.c - declared here to avoid pulling in jwt-private.h
 * which requires the full jwt.h public header. */
extern void *jwt_malloc(size_t size);

/* ================================================================
 * Internal helpers: cast between opaque jwt_json_t and json_object
 * ================================================================ */

static inline struct json_object *to_jc(const jwt_json_t *j)
{
	return (struct json_object *)j;
}

static inline jwt_json_t *from_jc(struct json_object *j)
{
	return (jwt_json_t *)j;
}

/* ================================================================
 * Memory allocator override
 * ================================================================ */

void jwt_json_set_alloc(void *(*alloc_func)(size_t),
			void (*free_func)(void *))
{
	/* json-c does not support custom allocators */
	(void)alloc_func;
	(void)free_func;
}

/* Internal flag masks - must match jwt-json-ops.h */
#define INDENT_MASK	0x1F
#define FLAG_COMPACT	0x20
#define FLAG_SORT_KEYS	0x80

/* ================================================================
 * Reference counting
 * ================================================================ */

void jwt_json_releasep(jwt_json_t **json)
{
	if (json && *json) {
		json_object_put(to_jc(*json));
		*json = NULL;
	}
}

void jwt_json_release(jwt_json_t *json)
{
	if (json)
		json_object_put(to_jc(json));
}

/* ================================================================
 * Object creation
 * ================================================================ */

jwt_json_t *jwt_json_create(void)
{
	return from_jc(json_object_new_object());
}

jwt_json_t *jwt_json_create_arr(void)
{
	return from_jc(json_object_new_array());
}

jwt_json_t *jwt_json_create_str(const char *value)
{
	if (!value)
		return NULL;
	return from_jc(json_object_new_string(value));
}

jwt_json_t *jwt_json_create_int(jwt_json_int_t value)
{
	return from_jc(json_object_new_int64(value));
}

jwt_json_t *jwt_json_create_bool(int value)
{
	return from_jc(json_object_new_boolean(value));
}

/* ================================================================
 * Object operations
 * ================================================================ */

jwt_json_t *jwt_json_obj_get(const jwt_json_t *object, const char *key)
{
	if (!object || !key)
		return NULL;
	return from_jc(json_object_object_get(to_jc(object), key));
}

int jwt_json_obj_set(jwt_json_t *object, const char *key, jwt_json_t *value)
{
	if (!object || !key || !value)
		return -1;
	return json_object_object_add(to_jc(object), key, to_jc(value));
}

int jwt_json_obj_del(jwt_json_t *object, const char *key)
{
	if (!object || !key)
		return -1;
	json_object_object_del(to_jc(object), key);
	return 0;
}

int jwt_json_obj_clear(jwt_json_t *object)
{
	const char **keys;
	int n = 0, i = 0;

	if (!object)
		return -1;

	json_object_object_foreach(to_jc(object), key, val) {
		(void)key;
		(void)val;
		n++;
	}

	if (n == 0)
		return 0;

	keys = malloc(n * sizeof(char *));
	if (!keys)
		return -1;

	json_object_object_foreach(to_jc(object), key2, val2) {
		(void)val2;
		keys[i++] = key2;
	}

	for (i = 0; i < n; i++)
		json_object_object_del(to_jc(object), keys[i]);

	free(keys);
	return 0;
}

int jwt_json_obj_merge(jwt_json_t *object, jwt_json_t *other)
{
	if (!object || !other)
		return -1;

	json_object_object_foreach(to_jc(other), key, val) {
		json_object_object_add(to_jc(object), key,
				       json_object_get(val));
	}

	return 0;
}

int jwt_json_obj_merge_new(jwt_json_t *object, jwt_json_t *other)
{
	if (!object || !other)
		return -1;

	json_object_object_foreach(to_jc(other), key, val) {
		struct json_object *existing;
		if (!json_object_object_get_ex(to_jc(object), key, &existing))
			json_object_object_add(to_jc(object), key,
					       json_object_get(val));
	}

	return 0;
}

/* ================================================================
 * Array operations
 * ================================================================ */

size_t jwt_json_arr_size(const jwt_json_t *array)
{
	if (!array)
		return 0;
	return json_object_array_length(to_jc(array));
}

jwt_json_t *jwt_json_arr_get(const jwt_json_t *array, size_t index)
{
	if (!array)
		return NULL;
	return from_jc(json_object_array_get_idx(to_jc(array), index));
}

int jwt_json_arr_append(jwt_json_t *array, jwt_json_t *value)
{
	if (!array)
		return -1;
	return json_object_array_add(to_jc(array), to_jc(value));
}

/* ================================================================
 * Type checking
 * ================================================================ */

int jwt_json_is_array(const jwt_json_t *json)
{
	return json && json_object_is_type(to_jc(json), json_type_array);
}

int jwt_json_is_string(const jwt_json_t *json)
{
	return json && json_object_is_type(to_jc(json), json_type_string);
}

int jwt_json_is_int(const jwt_json_t *json)
{
	return json && json_object_is_type(to_jc(json), json_type_int);
}

int jwt_json_is_bool(const jwt_json_t *json)
{
	return json && json_object_is_type(to_jc(json), json_type_boolean);
}

int jwt_json_is_true(const jwt_json_t *json)
{
	return json && json_object_is_type(to_jc(json), json_type_boolean) &&
	       json_object_get_boolean(to_jc(json));
}

/* ================================================================
 * Value extraction
 * ================================================================ */

const char *jwt_json_str_val(const jwt_json_t *json)
{
	if (!json)
		return NULL;
	return json_object_get_string(to_jc(json));
}

jwt_json_int_t jwt_json_int_val(const jwt_json_t *json)
{
	if (!json)
		return 0;
	return json_object_get_int64(to_jc(json));
}

/* ================================================================
 * Deep copy
 * ================================================================ */

jwt_json_t *jwt_json_clone(const jwt_json_t *value)
{
	struct json_object *dst = NULL;

	if (!value)
		return NULL;

	if (json_object_deep_copy(to_jc(value), &dst, NULL) != 0)
		return NULL;

	return from_jc(dst);
}

/* ================================================================
 * Sorted-key serialization
 *
 * json-c does not support sorted keys natively. We implement it
 * here because JWT requires deterministic output (RFC 7515).
 * ================================================================ */

static int key_cmp(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

static int append_str(char **buf, size_t *len, size_t *cap, const char *str)
{
	size_t slen = strlen(str);

	while (*len + slen + 1 > *cap) {
		*cap *= 2;
		char *tmp = realloc(*buf, *cap);
		if (!tmp)
			return -1;
		*buf = tmp;
	}
	memcpy(*buf + *len, str, slen);
	*len += slen;
	(*buf)[*len] = '\0';
	return 0;
}

static int serialize_value_sorted(struct json_object *json, int compact,
				  char **buf, size_t *len, size_t *cap)
{
	if (!json)
		return append_str(buf, len, cap, "null");

	enum json_type type = json_object_get_type(json);

	if (type == json_type_object) {
		int n = json_object_object_length(json);
		const char **keys = NULL;
		int i = 0;

		if (append_str(buf, len, cap, "{"))
			return -1;

		if (n > 0) {
			keys = malloc(n * sizeof(char *));
			if (!keys)
				return -1;

			json_object_object_foreach(json, key, val) {
				(void)val;
				keys[i++] = key;
			}

			qsort(keys, n, sizeof(char *), key_cmp);

			for (i = 0; i < n; i++) {
				struct json_object *v;
				const char *escaped;
				struct json_object *str_obj;

				if (i > 0) {
					if (append_str(buf, len, cap,
						       compact ? "," : ", ")) {
						free(keys);
						return -1;
					}
				}

				str_obj = json_object_new_string(keys[i]);
				escaped = json_object_to_json_string_ext(
					str_obj, JSON_C_TO_STRING_PLAIN);
				if (append_str(buf, len, cap, escaped)) {
					json_object_put(str_obj);
					free(keys);
					return -1;
				}
				json_object_put(str_obj);

				if (append_str(buf, len, cap,
					       compact ? ":" : ": ")) {
					free(keys);
					return -1;
				}

				json_object_object_get_ex(json, keys[i], &v);
				if (serialize_value_sorted(v, compact, buf,
							   len, cap)) {
					free(keys);
					return -1;
				}
			}

			free(keys);
		}

		return append_str(buf, len, cap, "}");

	} else if (type == json_type_array) {
		size_t arr_len = json_object_array_length(json);

		if (append_str(buf, len, cap, "["))
			return -1;

		for (size_t idx = 0; idx < arr_len; idx++) {
			struct json_object *elem;

			if (idx > 0) {
				if (append_str(buf, len, cap,
					       compact ? "," : ", "))
					return -1;
			}

			elem = json_object_array_get_idx(json, idx);
			if (serialize_value_sorted(elem, compact, buf,
						   len, cap))
				return -1;
		}

		return append_str(buf, len, cap, "]");

	} else {
		const char *str = json_object_to_json_string_ext(
			json, JSON_C_TO_STRING_PLAIN);
		return append_str(buf, len, cap, str);
	}
}

static int serialize_sorted(const jwt_json_t *json, int compact, char **out)
{
	size_t len = 0;
	size_t cap = 256;
	char *buf = malloc(cap);

	if (!buf)
		return -1;

	buf[0] = '\0';

	if (serialize_value_sorted(to_jc(json), compact, &buf, &len, &cap)) {
		free(buf);
		return -1;
	}

	*out = buf;
	return 0;
}

/* ================================================================
 * Serialization / Parsing
 * ================================================================ */

/**
 * Copy a libc-allocated string into a jwt_malloc-allocated buffer.
 * The caller is expected to free the result with jwt_freemem().
 */
static char *to_jwt_alloc(char *libc_str)
{
	size_t len;
	char *out;

	if (!libc_str)
		return NULL;

	len = strlen(libc_str) + 1;
	out = jwt_malloc(len);
	if (!out) {
		free(libc_str);
		return NULL;
	}

	memcpy(out, libc_str, len);
	free(libc_str);
	return out;
}

char *jwt_json_serialize(const jwt_json_t *json, size_t flags)
{
	char *result;

	if (!json)
		return NULL;

	if (flags & FLAG_SORT_KEYS) {
		int compact = (flags & FLAG_COMPACT) ? 1 : 0;

		if (serialize_sorted(json, compact, &result))
			return NULL;
		return to_jwt_alloc(result);
	}

	int jc_flags = JSON_C_TO_STRING_PLAIN;
	int indent = flags & INDENT_MASK;

	if (indent > 0)
		jc_flags = JSON_C_TO_STRING_PRETTY;

	const char *str = json_object_to_json_string_ext(to_jc(json), jc_flags);
	if (!str)
		return NULL;

	size_t len = strlen(str) + 1;
	result = jwt_malloc(len);
	if (!result)
		return NULL;

	memcpy(result, str, len);
	return result;
}

static void set_error(jwt_json_error_t *error, const char *source,
		      const char *text)
{
	if (!error)
		return;

	memset(error, 0, sizeof(*error));

	if (text)
		snprintf(error->text, JWT_JSON_ERROR_TEXT_LENGTH, "%s", text);
	if (source)
		snprintf(error->source, JWT_JSON_ERROR_SOURCE_LENGTH,
			 "%s", source);
}

/*
 * NOTE: json-c does not support JWT_JSON_REJECT_DUPLICATES.
 * Duplicate keys are silently accepted (last value wins).
 * This only affects jwt_set_json() where users manually set
 * JSON claims - it does not affect JWT verification of
 * received tokens.
 */

/**
 * Common post-parse validation for all parse functions.
 * Checks trailing garbage and enforces DECODE_ANY semantics.
 */
static jwt_json_t *validate_parsed(struct json_tokener *tok,
				   struct json_object *obj,
				   size_t input_len, size_t flags,
				   const char *source,
				   jwt_json_error_t *error)
{
	/* Reject trailing garbage */
	if (json_tokener_get_parse_end(tok) < input_len) {
		set_error(error, source, "Trailing data after JSON value");
		json_tokener_free(tok);
		if (obj)
			json_object_put(obj);
		return NULL;
	}

	json_tokener_free(tok);

	/* Without DECODE_ANY, only accept objects and arrays
	 * (matches jansson default behavior) */
	if (!(flags & JWT_JSON_DECODE_ANY)) {
		if (!json_object_is_type(obj, json_type_object) &&
		    !json_object_is_type(obj, json_type_array)) {
			set_error(error, source,
				  "Expected JSON object or array");
			json_object_put(obj);
			return NULL;
		}
	}

	return from_jc(obj);
}

jwt_json_t *jwt_json_parse(const char *input, size_t flags,
			   jwt_json_error_t *error)
{
	struct json_tokener *tok;
	struct json_object *obj;
	enum json_tokener_error jerr;

	if (!input) {
		set_error(error, "<string>", "NULL input");
		return NULL;
	}

	size_t slen = strlen(input);
	if (slen > INT_MAX) {
		set_error(error, "<string>", "Input too large");
		return NULL;
	}

	tok = json_tokener_new();
	if (!tok) {
		set_error(error, "<string>", "Failed to create tokener");
		return NULL;
	}

	obj = json_tokener_parse_ex(tok, input, (int)slen);
	jerr = json_tokener_get_error(tok);

	if (jerr != json_tokener_success) {
		set_error(error, "<string>",
			  json_tokener_error_desc(jerr));
		json_tokener_free(tok);
		if (obj)
			json_object_put(obj);
		return NULL;
	}

	return validate_parsed(tok, obj, slen, flags, "<string>", error);
}

jwt_json_t *jwt_json_parse_buf(const char *buffer, size_t buflen,
			       size_t flags, jwt_json_error_t *error)
{
	struct json_tokener *tok;
	struct json_object *obj;
	enum json_tokener_error jerr;

	if (!buffer) {
		set_error(error, "<buffer>", "NULL buffer");
		return NULL;
	}

	if (buflen > INT_MAX) {
		set_error(error, "<buffer>", "Buffer too large");
		return NULL;
	}

	tok = json_tokener_new();
	if (!tok) {
		set_error(error, "<buffer>", "Failed to create tokener");
		return NULL;
	}

	obj = json_tokener_parse_ex(tok, buffer, (int)buflen);
	jerr = json_tokener_get_error(tok);

	if (jerr != json_tokener_success) {
		set_error(error, "<buffer>",
			  json_tokener_error_desc(jerr));
		json_tokener_free(tok);
		if (obj)
			json_object_put(obj);
		return NULL;
	}

	return validate_parsed(tok, obj, buflen, flags, "<buffer>", error);
}

jwt_json_t *jwt_json_parse_file(const char *path, size_t flags,
				jwt_json_error_t *error)
{
	struct json_object *obj;

	if (!path) {
		set_error(error, "<file>", "NULL path");
		return NULL;
	}

	obj = json_object_from_file(path);
	if (!obj) {
		set_error(error, path, "Failed to parse file");
		return NULL;
	}

	if (!(flags & JWT_JSON_DECODE_ANY)) {
		if (!json_object_is_type(obj, json_type_object) &&
		    !json_object_is_type(obj, json_type_array)) {
			set_error(error, path,
				  "Expected JSON object or array");
			json_object_put(obj);
			return NULL;
		}
	}

	return from_jc(obj);
}

jwt_json_t *jwt_json_parse_fp(FILE *input, size_t flags,
			      jwt_json_error_t *error)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	char chunk[4096];
	size_t nread;
	jwt_json_t *result;

	if (!input) {
		set_error(error, "<file>", "NULL FILE pointer");
		return NULL;
	}

	while ((nread = fread(chunk, 1, sizeof(chunk), input)) > 0) {
		if (len + nread + 1 > cap) {
			cap = (cap == 0) ? 8192 : cap * 2;
			if (cap < len + nread + 1)
				cap = len + nread + 1;
			char *tmp = realloc(buf, cap);
			if (!tmp) {
				free(buf);
				set_error(error, "<file>",
					  "Memory allocation failed");
				return NULL;
			}
			buf = tmp;
		}
		memcpy(buf + len, chunk, nread);
		len += nread;
	}

	if (!buf) {
		set_error(error, "<file>", "Empty input");
		return NULL;
	}

	buf[len] = '\0';
	result = jwt_json_parse(buf, flags, error);
	free(buf);

	return result;
}
