/* Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
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

#define trace() fprintf(stderr, "%s:%d\n", __func__, __LINE__);

static void jwk_process_values(json_t *jwk, jwk_item_t *item)
{
	/* TODO Setup alg_list, ops, use, and kid. */
}

static jwk_item_t *jwk_process_one(jwk_set_t *jwk_set, json_t *jwk)
{
	const char *kty;
	json_t *val;
	jwk_item_t *item;

	item = jwt_malloc(sizeof(*item));
	if (item == NULL) {
		snprintf(jwk_set->error_msg, sizeof(jwk_set->error_msg),
			 "Error allocating memory for jwk_item_t");
		jwk_set->error = 1;
		return NULL;
	}

	memset(item, 0, sizeof(*item));

	val = json_object_get(jwk, "kty");
	if (val == NULL || !json_is_string(val)) {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Invalid JWK: missing kty value");
		item->error = 1;
		return item;
	}

	kty = json_string_value(val);

	if (!strcmp(kty, "EC")) {
		process_ec_jwk(jwk, item);
	} else if (!strcmp(kty, "RSA")) {
		process_rsa_jwk(jwk, item);
	} else if (!strcmp(kty, "OKP")) {
		process_eddsa_jwk(jwk, item);
	} else {
		snprintf(item->error_msg, sizeof(item->error_msg),
			 "Unknown kty type '%s'", kty);
		item->error = 1;
		return item;
	}

	jwk_process_values(jwk, item);

	return item;
}

jwk_item_t *jwks_item_get(jwk_set_t *jwk_set, size_t index)
{
	struct jwk_list_item *item = NULL;
	int i = 0;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (i > index)
			return NULL;
		if (i == index)
			return item->item;
		i++;
	}

	return NULL;
}

int jwks_error(jwk_set_t *jwk_set)
{
	return jwk_set->error ? 1 : 0;
}

int jwks_item_add(jwk_set_t *jwk_set, jwk_item_t *item)
{
	struct jwk_list_item *new;

	if (item == NULL || jwk_set == NULL)
		return EINVAL;

	new = jwt_malloc(sizeof(*new));
	if (new == NULL)
		return ENOMEM;

	new->item = item;

	list_add(&new->node, &jwk_set->head);

	return 0;
}

int jwks_item_free(jwk_set_t *jwk_set, size_t index)
{
	struct jwk_list_item *list_item = NULL, *todel = NULL;
	jwk_item_t *item;
        int i = 0;

	list_for_each_entry(list_item, &jwk_set->head, node) {
		if (i > index)
			return 0;
		if (i == index) {
			todel = list_item;
			break;
		}
		i++;
	}

	if (todel == NULL)
		return 0;

	item = todel->item;
	list_del(&todel->node);
	jwt_freemem(list_item);
	jwt_freemem(item->pem);
	jwt_freemem(item);

	return 1;
}

int jwks_item_free_all(jwk_set_t *jwk_set)
{
	int i;

	for (i = 0; jwks_item_free(jwk_set, 0); i++)
		/* do nothing */;

	return i;
}

void jwks_free(jwk_set_t *jwk_set)
{
	jwks_item_free_all(jwk_set);
	jwt_freemem(jwk_set);
}

jwk_set_t *jwks_create(const char *jwk_json_str)
{
	json_t *j_all = NULL, *j_array = NULL;
	json_t *j_item = NULL;
	json_error_t error;
	jwk_set_t *jwk_set;
	jwk_item_t *jwk_item;
	size_t i;

	errno = 0;

	jwk_set = jwt_malloc(sizeof *jwk_set);
	if (jwk_set == NULL) {
		/* Yes, malloc(3) will set this, but just in case. */
		errno = ENOMEM;
		return NULL;
	}

	memset(jwk_set, 0, sizeof(*jwk_set));
	INIT_LIST_HEAD(&jwk_set->head);

	/* Just an empty set */
	if (jwk_json_str == NULL) {
		return jwk_set;
	}

	/* Parse the JSON string. */
	j_all = json_loads(jwk_json_str, JSON_DECODE_ANY, &error);
	if (j_all == NULL) {
		jwk_set->error = 1;
		snprintf(jwk_set->error_msg, sizeof(jwk_set->error_msg),
			 "%s: %s", error.source, error.text);
		return jwk_set;
	}

	/* Check for "keys" as in a JWKS */
	j_array = json_object_get(j_all, "keys");

	if (j_array == NULL) {
		/* Assume a single JSON Object for one JWK */
		jwk_item = jwk_process_one(jwk_set, j_all);
		jwks_item_add(jwk_set, jwk_item);
	} else {
		/* We have a list, so parse them all. */
		json_array_foreach(j_array, i, j_item) {
			jwk_item = jwk_process_one(jwk_set, j_item);
			jwks_item_add(jwk_set, jwk_item);
		}
	}

	json_decref(j_all);

	return jwk_set;
}
