/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

static jwt_value_error_t jwt_get_str(jwt_json_t *which, jwt_value_t *jval)
{
	jwt_json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = jwt_json_obj_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!jwt_json_is_string(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->str_val = jwt_json_str_val(val);
	if (jval->str_val == NULL)
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_get_int(jwt_json_t *which, jwt_value_t *jval)
{
	jwt_json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = jwt_json_obj_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!jwt_json_is_int(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->int_val = jwt_json_int_val(val);

	return jval->error;
}

static jwt_value_error_t jwt_get_bool(jwt_json_t *which, jwt_value_t *jval)
{
	jwt_json_t *val;

	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	val = jwt_json_obj_get(which, jval->name);
	if (val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;
	else if (!jwt_json_is_bool(val))
		return jval->error = JWT_VALUE_ERR_TYPE;

	jval->bool_val = jwt_json_is_true(val) ? 1 : 0;

	return jval->error;
}

static jwt_value_error_t jwt_get_json(jwt_json_t *which, jwt_value_t *jval)
{
	jwt_json_t *json_val = NULL;
	size_t flags = JWT_JSON_SORT_KEYS;

	if (jval->pretty)
		flags |= JWT_JSON_INDENT(4);
	else
		flags |= JWT_JSON_COMPACT;

	if (jval->name && strlen(jval->name))
		json_val = jwt_json_obj_get(which, jval->name);
	else
		json_val = which;

	if (json_val == NULL)
		return jval->error = JWT_VALUE_ERR_NOEXIST;

	jval->json_val = jwt_json_serialize(json_val, flags);
	if (jval->json_val == NULL)
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_obj_check(jwt_json_t *which, jwt_value_t *jval)
{
	if (jwt_json_obj_get(which, jval->name)) {
		if (jval->replace)
			jwt_json_obj_del(which, jval->name);
		else
			return jval->error = JWT_VALUE_ERR_EXIST;
	}

	return JWT_VALUE_ERR_NONE;
}

static jwt_value_error_t jwt_set_str(jwt_json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name) || !jval->str_val)
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (jwt_json_obj_set(which, jval->name, jwt_json_create_str(jval->str_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_int(jwt_json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (jwt_json_obj_set(which, jval->name,
				jwt_json_create_int((jwt_json_int_t)jval->int_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_bool(jwt_json_t *which, jwt_value_t *jval)
{
	if (!jval->name || !strlen(jval->name))
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jwt_obj_check(which, jval))
		return jval->error;

	if (jwt_json_obj_set(which, jval->name, jwt_json_create_bool(jval->bool_val)))
		jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE

	return jval->error;
}

static jwt_value_error_t jwt_set_json(jwt_json_t *which, jwt_value_t *jval)
{
	size_t flags = JWT_JSON_REJECT_DUPLICATES;
	jwt_json_t *json_val = NULL;
	int ret;

	json_val = jwt_json_parse(jval->json_val, flags, NULL);

	/* Because we didn't set JSON_DECODE_ANY, we are guaranteed an array or
	 * object here. */
	if (!json_val)
		return jval->error = JWT_VALUE_ERR_INVALID;

	if (jval->name == NULL || !strlen(jval->name)) {
		/* Update the whole thing */
		if (jval->replace)
			ret = jwt_json_obj_merge(which, json_val);
		else
			ret = jwt_json_obj_merge_new(which, json_val);

		/* Done with this. */
		jwt_json_releasep(&json_val);

		if (ret)
			jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE
	} else {
		/* Add object at name */
		if (!jwt_obj_check(which, jval)) {
			if (jwt_json_obj_set(which, jval->name, json_val))
				jval->error = JWT_VALUE_ERR_INVALID; // LCOV_EXCL_LINE
		}

		/* If things failed, it means we're responsible for this ref */
		if (jval->error != JWT_VALUE_ERR_NONE)
			jwt_json_releasep(&json_val);
	}

	return jval->error;
}

jwt_value_error_t __deleter(jwt_json_t *which, const char *field)
{
	if (field == NULL || !strlen(field))
		jwt_json_obj_clear(which);
	else
		jwt_json_obj_del(which, field);

	return JWT_VALUE_ERR_NONE;
}

jwt_value_error_t __setter(jwt_json_t *which, jwt_value_t *value)
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

jwt_value_error_t __getter(jwt_json_t *which, jwt_value_t *value)
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

typedef jwt_value_error_t (*__doer_t)(jwt_json_t *, jwt_value_t *);

static jwt_value_error_t __run_it(jwt_t *jwt, _setget_type_t type,
				  jwt_value_t *value, __doer_t doer)
{
	jwt_json_t *which = NULL;

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

/* @rfc{7800} "cnf" (confirmation) claim helpers.
 *
 * cnf is a JSON object carrying a single proof-of-possession confirmation. The
 * issuer sets it on a builder; a verifier reads a member from the jwt_t handed
 * to its jwt_checker_setcb() callback (see jwt_get_cnf()). Each setter REPLACES
 * any existing cnf, so the object always holds exactly one member. */

/* Serialize the single-member object @cnf and set it as the builder's "cnf". */
static int builder_set_cnf(jwt_builder_t *builder, jwt_json_t *cnf)
{
	char_auto *json = NULL;
	jwt_value_t jval;

	json = jwt_json_serialize(cnf, JWT_JSON_COMPACT);
	if (json == NULL)
		return 1; // LCOV_EXCL_LINE

	jwt_set_SET_JSON(&jval, "cnf", json);
	jval.replace = 1;

	return jwt_builder_claim_set(builder, &jval) != JWT_VALUE_ERR_NONE;
}

int jwt_builder_setcnf(jwt_builder_t *builder, const char *member,
		       const char *value)
{
	jwt_json_auto_t *cnf = NULL;

	if (builder == NULL || member == NULL || !strlen(member) ||
	    value == NULL)
		return 1;

	cnf = jwt_json_create();
	if (cnf == NULL)
		return 1; // LCOV_EXCL_LINE

	if (jwt_json_obj_set(cnf, member, jwt_json_create_str(value)))
		return 1; // LCOV_EXCL_LINE

	return builder_set_cnf(builder, cnf);
}

int jwt_builder_setcnf_jkt(jwt_builder_t *builder, const jwk_item_t *key)
{
	char_auto *tp = NULL;

	if (builder == NULL || key == NULL)
		return 1;

	tp = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	if (tp == NULL)
		return 1;

	return jwt_builder_setcnf(builder, "jkt", tp);
}

int jwt_builder_setcnf_jwk(jwt_builder_t *builder, const jwk_item_t *key)
{
	jwt_json_auto_t *cnf = NULL;
	char_auto *jwk_json = NULL;
	jwt_json_t *jwk;

	if (builder == NULL || key == NULL)
		return 1;

	cnf = jwt_json_create();
	if (cnf == NULL)
		return 1; // LCOV_EXCL_LINE

	/* Embed the PUBLIC JWK only (@rfc{7800,3.2}). */
	jwk_json = jwks_item_export(key, 0);
	if (jwk_json == NULL)
		return 1; // LCOV_EXCL_LINE

	jwk = jwt_json_parse(jwk_json, 0, NULL);
	if (jwk == NULL)
		return 1; // LCOV_EXCL_LINE

	/* obj_set steals the jwk reference into cnf. */
	if (jwt_json_obj_set(cnf, "jwk", jwk))
		return 1; // LCOV_EXCL_LINE

	return builder_set_cnf(builder, cnf);
}

char *jwt_get_cnf(const jwt_t *jwt, const char *member)
{
	jwt_json_t *cnf, *val;
	const char *str;
	char *out;
	size_t len;

	if (jwt == NULL || jwt->claims == NULL || member == NULL)
		return NULL;

	cnf = jwt_json_obj_get(jwt->claims, "cnf");
	if (cnf == NULL || !jwt_json_is_object(cnf))
		return NULL;

	val = jwt_json_obj_get(cnf, member);
	if (val == NULL || !jwt_json_is_string(val))
		return NULL;

	str = jwt_json_str_val(val);
	if (str == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Return a copy: the borrowed value would dangle once the jwt_t (e.g. a
	 * verify callback's token) is freed. */
	len = strlen(str) + 1;
	out = jwt_malloc(len);
	if (out == NULL)
		return NULL; // LCOV_EXCL_LINE
	memcpy(out, str, len);

	return out;
}
