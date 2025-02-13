/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>
#include "jwt-private.h"

/* RFC-7517 4.3 */
static jwk_key_op_t jwk_key_op_j(json_t *j_op)
{
	const char *op;

	if (!j_op || !json_is_string(j_op))
		return JWK_KEY_OP_NONE;

	op = json_string_value(j_op);

	/* Should not be possible for this to happen. */
	if (op == NULL)
		return JWK_KEY_OP_NONE; // LCOV_EXCL_LINE

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
	if (j_alg) {
		if (!json_is_string(j_alg)) {
			 jwt_write_error(item, "Invalid alg type");
			 return;
		}
		item->alg = jwt_str_alg(json_string_value(j_alg));
	}

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
		size_t i;

		json_array_foreach(j_ops_a, i, j_op)
			item->key_ops |= jwk_key_op_j(j_op);;
	}

	/* Key ID (4.5). */
	j_kid = json_object_get(jwk, "kid");
	if (j_kid && json_is_string(j_kid)) {
		const char *kid = json_string_value(j_kid);
		int len = strlen(kid);

		if (len) {
			item->kid = jwt_malloc(len + 1);
			if (item->kid == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(item,
					"Error allocating memory for kid");
				// LCOV_EXCL_STOP
			} else { // LCOV_EXCL_LINE
				strcpy(item->kid, kid);
			}
		}
	}
}

static int process_octet(json_t *jwk, jwk_item_t *item)
{
	unsigned char *bin_k = NULL;
	const char *str_k;
	json_t *k;
	int len_k = 0;

	k = json_object_get(jwk, "k");
	if (k == NULL || !json_is_string(k)) {
		jwt_write_error(item, "Invalid JWK: missing `k`");
		return -1;
	}

	str_k = json_string_value(k);
	if (str_k == NULL || !strlen(str_k)) {
		jwt_write_error(item, "Invalid JWK: invalid `k`");
		return -1;
	}

	bin_k = jwt_base64uri_decode(str_k, &len_k);
	if (bin_k == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Invalid JWK: failed to decode `k`");
		return -1;
		// LCOV_EXCL_STOP
	}

	item->is_private_key = 1;
	item->provider = JWT_CRYPTO_OPS_ANY;
	item->oct.key = bin_k;
	item->oct.len = len_k;
	item->bits = len_k * 8;

	return 0;
}

static jwk_item_t *jwk_process_one(jwk_set_t *jwk_set, json_t *jwk)
{
	const char *kty;
	json_t *val;
	jwk_item_t *item;

	item = jwt_malloc(sizeof(*item));
	if (item == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwk_set,
			"Error allocating memory for jwk_item_t");
		return NULL;
		// LCOV_EXCL_STOP
	}

	memset(item, 0, sizeof(*item));
	item->json = json_deep_copy(jwk);
	if (item->json == NULL) {
		// LCOV_EXCL_START
		jwt_freemem(jwk);
		jwt_write_error(jwk_set,
			"Error allocating memory for jwk_item_t");
		return NULL;
		// LCOV_EXCL_STOP
	}

	val = json_object_get(item->json, "kty");
	if (val == NULL || !json_is_string(val)) {
		jwt_write_error(item, "Invalid JWK: missing kty value");
		return item;
	}

	kty = json_string_value(val);

	if (!jwt_strcmp(kty, "EC")) {
		item->kty = JWK_KEY_TYPE_EC;
		jwt_ops->process_ec(item->json, item);
	} else if (!jwt_strcmp(kty, "RSA")) {
		item->kty = JWK_KEY_TYPE_RSA;
		jwt_ops->process_rsa(item->json, item);
	} else if (!jwt_strcmp(kty, "OKP")) {
		item->kty = JWK_KEY_TYPE_OKP;
		jwt_ops->process_eddsa(item->json, item);
	} else if (!jwt_strcmp(kty, "oct")) {
		item->kty = JWK_KEY_TYPE_OCT;
		process_octet(item->json, item);
	} else {
		jwt_write_error(item, "Unknown or unsupported kty type '%s'", kty);
		return item;
	}

	jwk_process_values(item->json, item);

	return item;
}

const jwk_item_t *jwks_item_get(const jwk_set_t *jwk_set, size_t index)
{
	jwk_item_t *item = NULL;
	size_t i = 0;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (i == index)
			return item;
		i++;
	}

	return NULL;
}

int jwks_error_any(const jwk_set_t *jwk_set)
{
	jwk_item_t *item = NULL;
	int count = jwk_set->error;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (item->error)
			count++;
	}

	return count;
}

int jwks_item_is_private(const jwk_item_t *item)
{
	return item->is_private_key ? 1 : 0;
}

int jwks_item_error(const jwk_item_t *item)
{
	return item->error;
}

const char *jwks_item_error_msg(const jwk_item_t *item)
{
	return item->error_msg;
}

const char *jwks_item_curve(const jwk_item_t *item)
{
	return item->curve[0] ? item->curve : NULL;
}

const char *jwks_item_kid(const jwk_item_t *item)
{
	return item->kid;
}

jwt_alg_t jwks_item_alg(const jwk_item_t *item)
{
	return item->alg;
}

jwk_key_type_t jwks_item_kty(const jwk_item_t *item)
{
	return item->kty;
}

jwk_pub_key_use_t jwks_item_use(const jwk_item_t *item)
{
	return item->use;
}

jwk_key_op_t jwks_item_key_ops(const jwk_item_t *item)
{
	return item->key_ops;
}

const char *jwks_item_pem(const jwk_item_t *item)
{
	return item->pem;
}

int jwks_item_key_bits(const jwk_item_t *item)
{
	return item->bits;
}

int jwks_item_key_oct(const jwk_item_t *item, const unsigned char **buf,
		      size_t *len)
{
	if (!item->oct.key || !item->oct.len)
		return 1;

	*buf = item->oct.key;
	*len = item->oct.len;

	return 0;
}

int jwks_error(const jwk_set_t *jwk_set)
{
	return jwk_set->error ? 1 : 0;
}

const char *jwks_error_msg(const jwk_set_t *jwk_set)
{
	return jwk_set->error_msg;
}

void jwks_error_clear(jwk_set_t *jwk_set)
{
	jwk_set->error = 0;
	memset(jwk_set->error_msg, 0, sizeof(jwk_set->error_msg));
}

static int jwks_item_add(jwk_set_t *jwk_set, jwk_item_t *item)
{
	list_add_tail(&item->node, &jwk_set->head);

	return 0;
}

jwk_item_t *jwks_find_bykid(jwk_set_t *jwk_set, const char *kid)
{
	jwk_item_t *item = NULL;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (item->kid == NULL || strcmp(item->kid, kid))
			continue;
		return item;
        }

	return NULL;
}

static void __item_free(jwk_item_t *todel)
{
	if (todel->provider == JWT_CRYPTO_OPS_ANY)
		jwt_freemem(todel->oct.key);
	else
		jwt_ops->process_item_free(todel);

	/* A few non-crypto specific things. */
	jwt_freemem(todel->kid);
	json_decrefp(&todel->json);
	list_del(&todel->node);

	/* Free the container and the item itself. */
	jwt_freemem(todel);
}

int jwks_item_free(jwk_set_t *jwk_set, const size_t index)
{
	jwk_item_t *item = NULL, *todel = NULL;
	size_t i = 0;

	if (jwk_set == NULL)
		return 0;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (i == index) {
			todel = item;
			break;
		}
		i++;
	}

	if (todel == NULL)
		return 0;

	__item_free(todel);

	return 1;
}

size_t jwks_item_count(const jwk_set_t *jwk_set)
{
	size_t count = 0;
	jwk_item_t *item = NULL;

	list_for_each_entry(item, &jwk_set->head, node)
		count++;

	return count;
}

int jwks_item_free_bad(jwk_set_t *jwk_set)
{
	jwk_item_t *item, *pos;
	int count = 0;

	list_for_each_entry_safe(item, pos, &jwk_set->head, node) {
		if (!item->error)
			continue;
		__item_free(item);
		count++;
	}

	return count;
}

int jwks_item_free_all(jwk_set_t *jwk_set)
{
	int i;

	if (jwk_set == NULL)
		return 0;

	for (i = 0; jwks_item_free(jwk_set, 0); i++)
		/* do nothing */;

	return i;
}

void jwks_free(jwk_set_t *jwk_set)
{
	if (jwk_set == NULL)
		return;

	jwks_item_free_all(jwk_set);
	jwt_freemem(jwk_set);
}

static jwk_set_t *jwks_new(void)
{
	jwk_set_t *jwk_set;

	jwk_set = jwt_malloc(sizeof *jwk_set);
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(jwk_set, 0, sizeof(*jwk_set));
	INIT_LIST_HEAD(&jwk_set->head);

	return jwk_set;
}

static jwk_set_t *jwks_process(jwk_set_t *jwk_set, json_t *j_all, json_error_t *error)
{
	json_t *j_array = NULL, *j_item = NULL;
	jwk_item_t *jwk_item;
	size_t i;

	if (j_all == NULL) {
		jwt_write_error(jwk_set, "%s: %s", error->source, error->text);
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

        return jwk_set;
}

#define __FLAG_EMPTY	(void *)0xfffff00d
jwk_set_t *jwks_load_strn(jwk_set_t *jwk_set, const char *jwk_json_str,
			    const size_t len)
{
	json_auto_t *j_all = NULL;
	json_error_t error;

	if (jwk_json_str == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Just an empty set. */
	if (jwk_json_str == __FLAG_EMPTY)
		return jwk_set;

	/* Parse the JSON string. */
	j_all = json_loadb(jwk_json_str, len, JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_load(jwk_set_t *jwk_set, const char *jwk_json_str)
{
	const char *real_str = jwk_json_str;
	size_t len;

	if (real_str == NULL) {
		real_str = __FLAG_EMPTY;
		len = 0;
	} else {
		len = strlen(real_str);
	}

	return jwks_load_strn(jwk_set, real_str, len);
}

jwk_set_t *jwks_load_fromfile(jwk_set_t *jwk_set, const char *file_name)
{
	json_auto_t *j_all = NULL;
	json_error_t error;

	if (file_name == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Parse the JSON string. */
	j_all = json_load_file(file_name, JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_load_fromfp(jwk_set_t *jwk_set, FILE *input)
{
	json_auto_t *j_all = NULL;
	json_error_t error;

	if (input == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Parse the JSON string. */
	j_all = json_loadf(input, JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_create(const char *jwk_json_str)
{
	return jwks_load(NULL, jwk_json_str);
}

jwk_set_t *jwks_create_strn(const char *jwk_json_str, const size_t len)
{
	return jwks_load_strn(NULL, jwk_json_str, len);
}

jwk_set_t *jwks_create_fromfile(const char *file_name)
{
	return jwks_load_fromfile(NULL, file_name);
}

jwk_set_t *jwks_create_fromfp(FILE *input)
{
	return jwks_load_fromfp(NULL, input);
}
