/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

static jwt_value_error_t jwt_get_str(json_t *which, jwt_value_t *jval)
{
	json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = json_object_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!json_is_string(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->str_val = json_string_value(val);
	if (jval->str_val == NULL)
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_get_int(json_t *which, jwt_value_t *jval)
{
	json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = json_object_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!json_is_integer(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->int_val = (long)json_integer_value(val);

	return jval->error;
}

static jwt_value_error_t jwt_get_bool(json_t *which, jwt_value_t *jval)
{
	json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = json_object_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!json_is_boolean(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->bool_val = json_is_true(val) ? 1 : 0;

	return jval->error;
}

static jwt_value_error_t jwt_get_json(json_t *which, jwt_value_t *jval)
{
	json_t *json_val = NULL;
	size_t flags = JSON_SORT_KEYS;

	if (jval->pretty)
		flags |= JSON_INDENT(4);
	else
		flags |= JSON_COMPACT;

	if (jval->name && strlen(jval->name))
		json_val = json_object_get(which, jval->name);
	else
		json_val = which;

	if (json_val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;

	jval->json_val = json_dumps(json_val, flags);
	if (jval->json_val == NULL)
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_obj_check(json_t *which, jwt_value_t *jval)
{
	if (json_object_get(which, jval->name)) {
		if (jval->replace)
			json_object_del(which, jval->name);
		else
			return jval->error = JWT_VALUE_ERR_EXIST;
	}

	return JWT_VALUE_ERR_NONE;
}

static jwt_value_error_t jwt_set_str(json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name) || !jval->str_val)
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name, json_string(jval->str_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_int(json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name,
				json_integer((json_int_t)jval->int_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_bool(json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name, json_boolean(jval->bool_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_json(json_t *which, jwt_value_t *jval)
{
	size_t flags = JSON_REJECT_DUPLICATES;
	json_t *json_val = NULL;
	int ret;

	json_val = json_loads(jval->json_val, flags, NULL);

	/* Because we didn't set JSON_DECODE_ANY, we are guaranteed an array or
	 * object here. */
	if (!json_val)
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jval->name == NULL || !strlen(jval->name)) {
		/* Update the whole thing */
		if (jval->replace)
			ret = json_object_update(which, json_val);
		else
			ret = json_object_update_missing(which, json_val);

		if (ret)
			jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE
	} else {
		/* Add object at name */
		if (!jwt_obj_check(which, jval)) {
			if (json_object_set_new(which, jval->name, json_val))
				jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE
		}
	}

	if (jval->error != JWT_VALUE_ERR_NONE)
		json_decref(json_val);

	return jval->error;
}

jwt_value_error_t __deleter(json_t *which, const char *field)
{
	if (field == NULL || !strlen(field))
		json_object_clear(which);
	else
		json_object_del(which, field);

	return JWT_VALUE_ERR_NONE;
}

jwt_value_error_t __setter(json_t *which, jwt_value_t *value)
{
	if (!which)
		return value->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	value->error = JWT_VALUE_ERR_NONE;

	switch (value->type) {
	case JWT_VALUE_INT:
		return jwt_set_int(which, value);

	case JWT_VALUE_STR:
		return jwt_set_str(which, value);

	case JWT_VALUE_BOOL:
		return jwt_set_bool(which, value);

	case JWT_VALUE_JSON:
		return jwt_set_json(which, value);
	// LCOV_EXCL_START
	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	// LCOV_EXCL_STOP
	}
}

jwt_value_error_t __getter(json_t *which, jwt_value_t *value)
{
	if (!which)
		return value->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	value->error = JWT_VALUE_ERR_NONE;

	switch (value->type) {
	case JWT_VALUE_INT:
		return jwt_get_int(which, value);

	case JWT_VALUE_STR:
		return jwt_get_str(which, value);

	case JWT_VALUE_BOOL:
		return jwt_get_bool(which, value);

	case JWT_VALUE_JSON:
		return jwt_get_json(which, value);
	// LCOV_EXCL_START
	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	// LCOV_EXCL_STOP
	}
}

typedef enum {
	__HEADER,
	__CLAIM,
} _setget_type_t;

typedef jwt_value_error_t (*__doer_t)(json_t *, jwt_value_t *);

static jwt_value_error_t __run_it(jwt_t *jwt, _setget_type_t type,
				  jwt_value_t *value, __doer_t doer)
{
	json_t *which = NULL;

	if (!jwt || !value) {
		if (value)
			return value->error = JWT_VALUE_ERR_INVALID;
		return JWT_VALUE_ERR_INVALID;
	}

	switch (type) {
	case __HEADER:
		which = jwt->headers;
		break;
	case __CLAIM:
		which = jwt->claims;
		break;
	// LCOV_EXCL_START
	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	// LCOV_EXCL_STOP
	}

	return doer(which, value);
}

/* Headers */
jwt_value_error_t jwt_header_get(jwt_t *jwt, jwt_value_t *value)
{
	return __run_it(jwt, __HEADER, value, __getter);
}

jwt_value_error_t jwt_header_set(jwt_t *jwt, jwt_value_t *value)
{
	return __run_it(jwt, __HEADER, value, __setter);
}

jwt_value_error_t jwt_header_del(jwt_t *jwt, const char *header)
{
	if (!jwt)
		return JWT_VALUE_ERR_INVALID;
	return __deleter(jwt->headers, header);
}

/* Claims */
jwt_value_error_t jwt_claim_get(jwt_t *jwt, jwt_value_t *value)
{
	return __run_it(jwt, __CLAIM, value, __getter);
}

jwt_value_error_t jwt_claim_set(jwt_t *jwt, jwt_value_t *value)
{
	return __run_it(jwt, __CLAIM, value, __setter);
}

jwt_value_error_t jwt_claim_del(jwt_t *jwt, const char *claim)
{
	if (!jwt)
                return JWT_VALUE_ERR_INVALID;
	return __deleter(jwt->claims, claim);
}
