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

int jwt_valid_new(jwt_valid_t **jwt_valid, jwt_alg_t alg)
{
	if (!jwt_valid)
		return EINVAL;

	*jwt_valid = jwt_malloc(sizeof(jwt_valid_t));
	if (!*jwt_valid)
		return ENOMEM; // LCOV_EXCL_LINE

	memset(*jwt_valid, 0, sizeof(jwt_valid_t));
	(*jwt_valid)->alg = alg;

	(*jwt_valid)->status = JWT_VALIDATION_ERROR;

	(*jwt_valid)->nbf_leeway = 0;
	(*jwt_valid)->exp_leeway = 0;

	(*jwt_valid)->req_grants = json_object();
	if (!(*jwt_valid)->req_grants) {
		jwt_freemem(*jwt_valid);
		return ENOMEM;
	}

	return 0;
}

void jwt_valid_free(jwt_valid_t *jwt_valid)
{
	if (!jwt_valid)
		return;

	json_decref(jwt_valid->req_grants);

	jwt_freemem(jwt_valid);
}

jwt_valid_exception_t jwt_valid_get_status(jwt_valid_t *jwt_valid)
{
	if (!jwt_valid)
		return JWT_VALIDATION_ERROR;

	return jwt_valid->status;
}

time_t jwt_valid_get_nbf_leeway(jwt_valid_t *jwt_valid)
{
	if (!jwt_valid)
		return EINVAL;

	return jwt_valid->nbf_leeway;
}

time_t jwt_valid_get_exp_leeway(jwt_valid_t *jwt_valid)
{
	if (!jwt_valid)
		return EINVAL;

	return jwt_valid->exp_leeway;
}

int jwt_valid_add_grant(jwt_valid_t *jwt_valid, const char *grant, const char *val)
{
	if (!jwt_valid || !grant || !strlen(grant) || !val)
		return EINVAL;

	if (get_js_string(jwt_valid->req_grants, grant) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt_valid->req_grants, grant, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_valid_add_grant_int(jwt_valid_t *jwt_valid, const char *grant, long val)
{
	if (!jwt_valid || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt_valid->req_grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt_valid->req_grants, grant, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_valid_add_grant_bool(jwt_valid_t *jwt_valid, const char *grant, int val)
{
	if (!jwt_valid || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_bool(jwt_valid->req_grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt_valid->req_grants, grant, json_boolean(val)))
		return EINVAL;

	return 0;
}

int jwt_valid_add_grants_json(jwt_valid_t *jwt_valid, const char *json)
{
	json_auto_t *js_val = NULL;
	int ret = -1;

	if (!jwt_valid)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt_valid->req_grants, js_val);

	return ret ? EINVAL : 0;
}

char *jwt_valid_get_grants_json(jwt_valid_t *jwt_valid, const char *grant)
{
	json_t *js_val = NULL;

	errno = EINVAL;

	if (!jwt_valid)
		return NULL;

	if (grant && strlen(grant))
		js_val = json_object_get(jwt_valid->req_grants, grant);
	else
		js_val = jwt_valid->req_grants;

	if (js_val == NULL)
		return NULL;

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

const char *jwt_valid_get_grant(jwt_valid_t *jwt_valid, const char *grant)
{
	if (!jwt_valid || !grant || !strlen(grant)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt_valid->req_grants, grant);
}

long jwt_valid_get_grant_int(jwt_valid_t *jwt_valid, const char *grant)
{
	if (!jwt_valid || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt_valid->req_grants, grant);
}

int jwt_valid_get_grant_bool(jwt_valid_t *jwt_valid, const char *grant)
{
	if (!jwt_valid || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_bool(jwt_valid->req_grants, grant);
}

int jwt_valid_set_now(jwt_valid_t *jwt_valid, const time_t now)
{
	if (!jwt_valid)
		return EINVAL;

	jwt_valid->now = now;

	return 0;
}

int jwt_valid_set_nbf_leeway(jwt_valid_t *jwt_valid, const time_t nbf_leeway)
{
	if (!jwt_valid)
		return EINVAL;

	jwt_valid->nbf_leeway = nbf_leeway;

	return 0;
}

int jwt_valid_set_exp_leeway(jwt_valid_t *jwt_valid, const time_t exp_leeway)
{
	if (!jwt_valid)
		return EINVAL;

	jwt_valid->exp_leeway = exp_leeway;

	return 0;
}

int jwt_valid_set_headers(jwt_valid_t *jwt_valid, int hdr)
{
	if (!jwt_valid)
		return EINVAL;

	jwt_valid->hdr = hdr;

	return 0;
}

int jwt_valid_del_grants(jwt_valid_t *jwt_valid, const char *grant)
{
	if (!jwt_valid)
		return EINVAL;

	if (grant == NULL || !strlen(grant))
		json_object_clear(jwt_valid->req_grants);
	else
		json_object_del(jwt_valid->req_grants, grant);

	return 0;
}

#define _SET_AND_RET(__v, __e) do {	\
	__v->status |= __e;		\
	return __v->status;		\
} while (0)

jwt_valid_exception_t jwt_validate(jwt_t *jwt, jwt_valid_t *jwt_valid)
{
	const char *jwt_hdr_str, *jwt_body_str, *req_grant;
	json_t *js_val_1, *js_val_2;
	time_t t;

	if (!jwt_valid)
		return JWT_VALIDATION_ERROR;

	if (!jwt) {
		jwt_valid->status = JWT_VALIDATION_ERROR;
		return jwt_valid->status;
	}

	jwt_valid->status = JWT_VALIDATION_SUCCESS;

	/* Validate algorithm */
	if (jwt_valid->alg != jwt_get_alg(jwt))
		jwt_valid->status |= JWT_VALIDATION_ALG_MISMATCH;

	/* Validate expires */
	t = get_js_int(jwt->grants, "exp");
	if (jwt_valid->now && t != -1 && jwt_valid->now - jwt_valid->exp_leeway >= t)
		jwt_valid->status |= JWT_VALIDATION_EXPIRED;

	/* Validate not-before */
	t = get_js_int(jwt->grants, "nbf");
	if (jwt_valid->now && t != -1 && jwt_valid->now + jwt_valid->nbf_leeway < t)
		jwt_valid->status |= JWT_VALIDATION_TOO_NEW;

	/* Validate replicated issuer */
	jwt_hdr_str = get_js_string(jwt->headers, "iss");
	jwt_body_str = get_js_string(jwt->grants, "iss");
	if (jwt_hdr_str && jwt_body_str && jwt_strcmp(jwt_hdr_str, jwt_body_str))
		jwt_valid->status |= JWT_VALIDATION_ISS_MISMATCH;

	/* Validate replicated subject */
	jwt_hdr_str = get_js_string(jwt->headers, "sub");
	jwt_body_str = get_js_string(jwt->grants, "sub");
	if (jwt_hdr_str && jwt_body_str && jwt_strcmp(jwt_hdr_str, jwt_body_str))
		jwt_valid->status |= JWT_VALIDATION_SUB_MISMATCH;

	/* Validate replicated audience (might be array or string) */
	js_val_1 = json_object_get(jwt->headers, "aud");
	js_val_2 = json_object_get(jwt->grants, "aud");
	if (js_val_1 && js_val_2 && !json_equal(js_val_1, js_val_2))
		jwt_valid->status |= JWT_VALIDATION_AUD_MISMATCH;

	/* Validate required grants */
	json_object_foreach(jwt_valid->req_grants, req_grant, js_val_1) {
		json_t *act_js_val = json_object_get(jwt->grants, req_grant);

		if (act_js_val && json_equal(js_val_1, act_js_val))
			continue;

		if (act_js_val)
			jwt_valid->status |= JWT_VALIDATION_GRANT_MISMATCH;
		else
			jwt_valid->status |= JWT_VALIDATION_GRANT_MISSING;
	}

	return jwt_valid->status;
}

typedef struct {
	int error;
	char *str;
} jwt_exception_dict_t;

static jwt_exception_dict_t jwt_exceptions[] = {
	/* { JWT_VALIDATION_SUCCESS, "SUCCESS" }, */
	{ JWT_VALIDATION_ERROR, "general failures" },
	{ JWT_VALIDATION_ALG_MISMATCH, "algorithm mismatch" },
	{ JWT_VALIDATION_EXPIRED, "token expired" },
	{ JWT_VALIDATION_TOO_NEW, "token future dated" },
	{ JWT_VALIDATION_ISS_MISMATCH, "issuer mismatch" },
	{ JWT_VALIDATION_SUB_MISMATCH, "subject mismatch" },
	{ JWT_VALIDATION_AUD_MISMATCH, "audience mismatch" },
	{ JWT_VALIDATION_GRANT_MISSING, "grant missing" },
	{ JWT_VALIDATION_GRANT_MISMATCH, "grant mismatch" },
};

char *jwt_exception_str(jwt_valid_exception_t exceptions)
{
	int rc, i;
	char *str = NULL;

	if (exceptions == JWT_VALIDATION_SUCCESS) {
		if ((rc = __append_str(&str, "success")))
			goto fail;
		return str;
	}

	for (i = 0; i < ARRAY_SIZE(jwt_exceptions); i++) {
		if (!(jwt_exceptions[i].error & exceptions))
			continue;

		if (str && (rc = __append_str(&str, ", ")))
			goto fail;

		if ((rc = __append_str(&str, jwt_exceptions[i].str)))
			goto fail;
	}

	/* check if none of the exceptions matched? */
	if (!str && (rc = __append_str(&str, "unknown exceptions")))
		goto fail;

	return str;
fail:
	errno = rc;
	jwt_freemem(str);
	return NULL;
}
