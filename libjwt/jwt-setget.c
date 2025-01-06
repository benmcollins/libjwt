/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <jwt.h>

#include "jwt-private.h"

const char *jwt_get_grant(const jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->grants, grant);
}

long jwt_get_grant_int(const jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->grants, grant);
}

int jwt_get_grant_bool(const jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_bool(jwt->grants, grant);
}

char *jwt_get_grants_json(const jwt_t *jwt, const char *grant)
{
	json_t *js_val = NULL;

	if (!jwt) {
		errno = EINVAL;
		return NULL;
	}

	if (grant && strlen(grant))
		js_val = json_object_get(jwt->grants, grant);
	else
		js_val = jwt->grants;

	if (js_val == NULL) {
		errno = ENOENT;
		return NULL;
	}

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT |
			  JSON_ENCODE_ANY);
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	if (!jwt || !grant || !strlen(grant) || !val)
		return EINVAL;

	if (get_js_string(jwt->grants, grant) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_add_grant_int(jwt_t *jwt, const char *grant, long val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt->grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_add_grant_bool(jwt_t *jwt, const char *grant, int val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt->grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_boolean(val)))
		return EINVAL;

	return 0;
}

int jwt_add_grants_json(jwt_t *jwt, const char *json)
{
	json_auto_t *js_val = NULL;
	int ret = -1;

	if (!jwt)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt->grants, js_val);

	return ret ? EINVAL : 0;
}

int jwt_del_grants(jwt_t *jwt, const char *grant)
{
	if (!jwt)
		return EINVAL;

	if (grant == NULL || !strlen(grant))
		json_object_clear(jwt->grants);
	else
		json_object_del(jwt->grants, grant);

	return 0;
}

const char *jwt_get_header(const jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->headers, header);
}

long jwt_get_header_int(const jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->headers, header);
}

int jwt_get_header_bool(const jwt_t *jwt, const char *header)
{
	if (!jwt || !header || !strlen(header)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_bool(jwt->headers, header);
}

char *jwt_get_headers_json(const jwt_t *jwt, const char *header)
{
	json_t *js_val = NULL;

	errno = EINVAL;

	if (!jwt)
		return NULL;

	if (header && strlen(header))
		js_val = json_object_get(jwt->headers, header);
	else
		js_val = jwt->headers;

	if (js_val == NULL)
		return NULL;

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

int jwt_add_header(jwt_t *jwt, const char *header, const char *val)
{
	if (!jwt || !header || !strlen(header) || !val)
		return EINVAL;

	if (get_js_string(jwt->headers, header) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_add_header_int(jwt_t *jwt, const char *header, long val)
{
	if (!jwt || !header || !strlen(header))
		return EINVAL;

	if (get_js_int(jwt->headers, header) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_add_header_bool(jwt_t *jwt, const char *header, int val)
{
	if (!jwt || !header || !strlen(header))
		return EINVAL;

	if (get_js_int(jwt->headers, header) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->headers, header, json_boolean(val)))
		return EINVAL;

	return 0;
}

int jwt_add_headers_json(jwt_t *jwt, const char *json)
{
	json_auto_t *js_val = NULL;
	int ret = -1;

	if (!jwt)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt->headers, js_val);

	return ret ? EINVAL : 0;
}

int jwt_del_headers(jwt_t *jwt, const char *header)
{
	if (!jwt)
		return EINVAL;

	if (header == NULL || !strlen(header))
		json_object_clear(jwt->headers);
	else
		json_object_del(jwt->headers, header);

	return 0;
}
