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

/* RFC-7517 4.3 */
static jwk_key_op_t jwk_key_op_j(json_t *j_op)
{
	const char *op;

	if (!j_op || !json_is_string(j_op))
		return JWK_KEY_OP_NONE;

	op = json_string_value(j_op);

	if (op == NULL)
		return JWK_KEY_OP_NONE;

	if (!jwt_strcmp(op, "sign"))
		return JWK_KEY_OP_SIGN;
	else if (!jwt_strcmp(op, "verify"))
		return JWK_KEY_OP_VERIFY;
	else if (!jwt_strcmp(op, "encrypt"))
		return JWK_KEY_OP_ENCRYPT;
	else if (!jwt_strcmp(op, "decrypt"))
		return JWK_KEY_OP_DECRYPT;
	else if (!jwt_strcmp(op, "wrapKey"))
		return JWK_KEY_OP_WRAP;
	else if (!jwt_strcmp(op, "unwrapKey"))
		return JWK_KEY_OP_UNWRAP;
	else if (!jwt_strcmp(op, "deriveKey"))
		return JWK_KEY_OP_DERIVE_KEY;
	else if (!jwt_strcmp(op, "deriveBits"))
		return JWK_KEY_OP_DERIVE_BITS;

	/* Ignore all others as the spec says other values may be used. */

	return JWK_KEY_OP_NONE;
}

static void jwk_process_values(json_t *jwk, jwk_item_t *item)
{
	json_t *j_use, *j_ops_a, *j_kid, *j_alg;

	/* Start with the ALG (4.4). */
	j_alg = json_object_get(jwk, "alg");
	if (j_alg && json_is_string(j_alg))
		item->alg = jwt_str_alg(json_string_value(j_alg));

	/* Check for use (4.2). */
	j_use = json_object_get(jwk, "use");
	if (j_use && json_is_string(j_use)) {
		const char *use = json_string_value(j_use);
		if (!jwt_strcmp(use, "sig"))
			item->use = JWK_PUB_KEY_USE_SIG;
		else if (!jwt_strcmp(use, "enc"))
			item->use = JWK_PUB_KEY_USE_ENC;
	}

	/* Check for key_ops (4.3). */
	j_ops_a = json_object_get(jwk, "key_ops");
	if (j_ops_a && json_is_array(j_ops_a)) {
		json_t *j_op;
		int i;

		json_array_foreach(j_ops_a, i, j_op) {
			item->key_ops |= jwk_key_op_j(j_op);
		}
	}

	/* Key ID (4.5). */
	j_kid = json_object_get(jwk, "kid");
	if (j_kid && json_is_string(j_kid)) {
		const char *kid = json_string_value(j_kid);
		int len = strlen(kid);

		if (len) {
			item->kid = jwt_malloc(len + 1);
			if (item->kid == NULL) {
				jwks_write_error(item,
					"Error allocating memory for kid");
			} else {
				strcpy(item->kid, kid);
			}
		}
	}
}

static jwk_item_t *jwk_process_one(jwk_set_t *jwk_set, json_t *jwk)
{
	const char *kty;
	json_t *val;
	jwk_item_t *item;

	item = jwt_malloc(sizeof(*item));
	if (item == NULL) {
		jwks_write_error(jwk_set,
			"Error allocating memory for jwk_item_t");
		return NULL;
	}

	memset(item, 0, sizeof(*item));

	val = json_object_get(jwk, "kty");
	if (val == NULL || !json_is_string(val)) {
		jwks_write_error(item, "Invalid JWK: missing kty value");
		return item;
	}

	kty = json_string_value(val);

	if (!jwt_strcmp(kty, "EC")) {
		item->kty = JWK_KEY_TYPE_EC;
		jwt_ops->process_ec(jwk, item);
	} else if (!jwt_strcmp(kty, "RSA")) {
		item->kty = JWK_KEY_TYPE_RSA;
		jwt_ops->process_rsa(jwk, item);
	} else if (!jwt_strcmp(kty, "OKP")) {
		item->kty = JWK_KEY_TYPE_OKP;
		jwt_ops->process_eddsa(jwk, item);
	} else {
		jwks_write_error(item, "Unknown or unsupported kty type '%s'", kty);
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

const char *jwks_error_msg(jwk_set_t *jwk_set)
{
	return jwk_set->error_msg;
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
		if (i == index) {
			todel = list_item;
			break;
		}
		i++;
	}

	if (todel == NULL)
		return 0;

	item = todel->item;

	/* Let the crypto ops clean their stuff up. */
	jwt_ops->process_item_free(item);

	/* A few non-crypto specific things. */
	jwt_freemem(item->kid);
	list_del(&todel->node);

	/* Free the container and the item itself. */
	jwt_freemem(list_item);
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

	if (!jwt_crypto_ops_supports_jwk()) {
		errno = ENOSYS;
		return NULL;
	}

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
