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

static jwt_value_error_t jwt_get_str(const jwt_t *jwt, json_t *which,
				     jwt_value_t *jval)
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
		jval->error = JWT_VALUE_ERR_INVALID;

	return jval->error;
}

static jwt_value_error_t jwt_get_int(const jwt_t *jwt, json_t *which,
				     jwt_value_t *jval)
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

static jwt_value_error_t jwt_get_bool(const jwt_t *jwt, json_t *which,
				      jwt_value_t *jval)
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

static jwt_value_error_t jwt_get_json(const jwt_t *jwt, json_t *which,
				      jwt_value_t *jval)
{
	json_t *json_val = NULL;
	size_t flags = JSON_SORT_KEYS | JSON_ENCODE_ANY;

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
		jval->error = JWT_VALUE_ERR_NOMEM;

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

static jwt_value_error_t jwt_add_str(jwt_t *jwt, json_t *which,
				     jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name) || !jval->str_val)
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name, json_string(jval->str_val)))
		jval->error = JWT_VALUE_ERR_INVALID;

	return jval->error;
}

static jwt_value_error_t jwt_add_int(jwt_t *jwt, json_t *which,
				     jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name,
				json_integer((json_int_t)jval->int_val)))
		jval->error = JWT_VALUE_ERR_INVALID;

	return jval->error;
}

static jwt_value_error_t jwt_add_bool(jwt_t *jwt, json_t *which,
				      jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (json_object_set_new(which, jval->name, json_boolean(jval->bool_val)))
		jval->error = JWT_VALUE_ERR_INVALID;

	return jval->error;
}

static jwt_value_error_t jwt_add_json(jwt_t *jwt, json_t *which,
				      jwt_value_t *jval)
{
	json_auto_t *json_val;
	int ret;

	json_val = json_loads(jval->json_val, JSON_REJECT_DUPLICATES, NULL);

	if (!json_is_object(json_val))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jval->name == NULL) {
		/* Update the whole thing */
		if (jval->replace)
			ret = json_object_update(which, json_val);
		else
			ret = json_object_update_missing(which, json_val);

		if (ret)
			return jval->error = JWT_VALUE_ERR_INVALID;
	} else {
		/* Add object at name */
		if (jwt_obj_check(which, jval))
			return jval->error;

		if (json_object_set_new(which, jval->name, json_val))
			return jval->error = JWT_VALUE_ERR_INVALID;
	}

	return jval->error;
}

static jwt_value_error_t __deleter(jwt_t *jwt, json_t *which, const char *field)
{
	if (!jwt)
		return JWT_VALUE_ERR_INVALID;

	if (field == NULL || !strlen(field))
		json_object_clear(which);
	else
		json_object_del(which, field);

	return JWT_VALUE_ERR_NONE;
}

static jwt_value_error_t __adder(jwt_t *jwt, json_t *which, jwt_value_t *value)
{
	if (!jwt || !value || !which) {
		if (value)
			return value->error = JWT_VALUE_ERR_INVALID;
		else
			return JWT_VALUE_ERR_INVALID;
	}

	value->error = JWT_VALUE_ERR_NONE;

	switch (value->type) {
	case JWT_VALUE_INT:
		return jwt_add_int(jwt, which, value);

	case JWT_VALUE_STR:
		return jwt_add_str(jwt, which, value);

	case JWT_VALUE_BOOL:
		return jwt_add_bool(jwt, which, value);

	case JWT_VALUE_JSON:
		return jwt_add_json(jwt, which, value);

	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	}
}

static jwt_value_error_t __getter(jwt_t *jwt, json_t *which, jwt_value_t *value)
{
	if (!jwt || !value || !which) {
		if (value)
			return value->error = JWT_VALUE_ERR_INVALID;
		else
			return JWT_VALUE_ERR_INVALID;
	}

	value->error = JWT_VALUE_ERR_NONE;

	switch (value->type) {
	case JWT_VALUE_INT:
		return jwt_get_int(jwt, which, value);

	case JWT_VALUE_STR:
		return jwt_get_str(jwt, which, value);

	case JWT_VALUE_BOOL:
		return jwt_get_bool(jwt, which, value);

	case JWT_VALUE_JSON:
		return jwt_get_json(jwt, which, value);

	default:
		return value->error = JWT_VALUE_ERR_INVALID;
	}
}

/* Headers */
jwt_value_error_t jwt_header_get(jwt_t *jwt, jwt_value_t *value)
{
	return __getter(jwt, jwt ? jwt->headers : NULL, value);
}

jwt_value_error_t jwt_header_add(jwt_t *jwt, jwt_value_t *value)
{
	return __adder(jwt, jwt ? jwt->headers : NULL, value);
}

jwt_value_error_t jwt_header_del(jwt_t *jwt, const char *header)
{
	return __deleter(jwt, jwt ? jwt->headers : NULL, header);
}

/* Grants */
jwt_value_error_t jwt_grant_get(jwt_t *jwt, jwt_value_t *value)
{
	return __getter(jwt, jwt ? jwt->grants : NULL, value);
}

jwt_value_error_t jwt_grant_add(jwt_t *jwt, jwt_value_t *value)
{
	return __adder(jwt, jwt ? jwt->grants : NULL, value);
}

jwt_value_error_t jwt_grant_del(jwt_t *jwt, const char *grant)
{
	return __deleter(jwt, jwt ? jwt->grants : NULL, grant);
}
