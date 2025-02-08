/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"

START_TEST(new)
{
	jwt_builder_auto_t *builder = NULL;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

}
END_TEST

START_TEST(gen)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_mem_eq(out, exp, strlen(exp));
}
END_TEST

static int __gen_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t jval;

	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);

	ck_assert_str_eq(config->ctx, "testing");
	jwt_set_ADD_INT(&jval, "exp", TS_CONST + 480);
	jwt_claim_add(jwt, &jval);

	return 0;
}

START_TEST(gen_wcb)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJleHAiOjE0NzU5ODEwMjV9.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	ret = jwt_builder_setcb(builder, __gen_wcb, "testing");
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);


}
END_TEST

START_TEST(gen_stress)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.";
	jwt_builder_auto_t *builder = NULL;
	int i;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	for (i = 0; i < 1000; i++) {
		char_auto *out = jwt_builder_generate(builder);
		ck_assert_ptr_nonnull(out);
		ck_assert_mem_eq(out, exp, strlen(exp));
	}

	ck_assert_int_eq(i, 1000);
}
END_TEST

START_TEST(null_handling)
{
	jwt_builder_t *builder = NULL;
	jwt_value_t jval;
	const char *out;
	jwk_item_t *key = NULL;
	int ret;

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	jwt_builder_free(NULL);

	ret = jwt_builder_setkey(NULL, JWT_ALG_HS256, NULL);
	ck_assert_int_ne(ret, 0);

	/* Create and clear an error */
	ret = jwt_builder_setkey(builder, JWT_ALG_HS256, NULL);
	ck_assert_int_ne(ret, 0);
	/* Check error exists */
	ck_assert_int_ne(jwt_builder_error(builder), 0);
	out = jwt_builder_error_msg(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_ne(strlen(out), 0);
	/* Clear it */
	jwt_builder_error_clear(builder);
	/* Check that its cleared */
	ck_assert_int_eq(jwt_builder_error(builder), 0);
	out = jwt_builder_error_msg(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(strlen(out), 0);

	/* Fake it */
	key = (void *)builder;
	ret = jwt_builder_setkey(NULL, 0, key);
	ck_assert_int_ne(ret, 0);

	ret = jwt_builder_error(NULL);
	ck_assert_int_ne(ret, 0);

	out = jwt_builder_error_msg(NULL);
	ck_assert_ptr_null(out);

	out = jwt_builder_error_msg(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(strlen(out), 0);

	jwt_builder_error_clear(NULL);

	out = jwt_builder_generate(NULL);
	ck_assert_ptr_null(out);

	/* Some alg mismatches */
	read_json("eddsa_key_ed25519.json");
        ret = jwt_builder_setkey(builder, JWT_ALG_NONE, g_item);
        ck_assert_int_ne(ret, 0);

        jwt_builder_error_clear(builder);

	read_json("oct_key_256.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_ES256, g_item);
	ck_assert_int_ne(ret, 0);

	jwt_builder_error_clear(builder);

	ret = jwt_builder_setcb(builder, NULL, "test");
	ck_assert_int_ne(ret, 0);

	ret = jwt_builder_header_del(NULL, NULL);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_claim_del(NULL, NULL);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_claim_add(NULL, &jval);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_claim_get(NULL, NULL);
	ck_assert_int_ne(ret, 0);

	/* Random */
	ck_assert_int_eq(jwt_str_alg(NULL), JWT_ALG_INVAL);

	out = jwt_alg_str(JWT_ALG_ES256K);
	ck_assert_str_eq(out, "ES256K");

	ck_assert_ptr_null(jwt_alg_str(JWT_ALG_INVAL));

	ck_assert_int_eq(jwt_get_alg(NULL), JWT_ALG_INVAL);

	ret = jwt_builder_setcb(NULL, NULL, NULL);
	ck_assert_int_ne(ret, 0);

	ck_assert_int_eq(jwt_header_del(NULL, NULL), JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(jwt_claim_del(NULL, NULL), JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(jwt_header_get(NULL, NULL), JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(jwt_header_get(NULL, &jval), JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(jval.error, JWT_VALUE_ERR_INVALID);
}
END_TEST

START_TEST(gen_hs256)
{
	jwt_builder_auto_t *builder = NULL;
	char *out = NULL;
	const char exp[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);

	free_key();
}
END_TEST

START_TEST(gen_hs256_bits)
{
	jwt_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_HS384, g_item);
	ck_assert_int_ne(ret, 0);

	free_key();
}
END_TEST

START_TEST(claims_set_errors)
{
	jwt_builder_auto_t *builder = NULL;
	char *out = NULL;
	const char exp[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.";
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_DEFAULT);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_mem_eq(out, exp, strlen(exp));

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE | JWT_CLAIM_SUB);
	ck_assert_int_ne(ret, 0);

	ret = jwt_builder_setclaims(builder, ~JWT_CLAIM_NONE);
	ck_assert_int_ne(ret, 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_AUD);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(gen_es384_pub)
{
	jwt_builder_auto_t *builder = NULL;
	const unsigned char *buf = NULL;
	jwk_key_type_t kty;
	const char *crv;
	size_t len = 0;
	int ret, bits;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	/* Pub key */
	read_json("ec_key_secp384r1_pub.json");

	/* Check the curve */
	crv = jwks_item_curve(g_item);
	ck_assert_str_eq(crv, "P-384");

	/* Check kty */
	kty = jwks_item_kty(g_item);
	ck_assert_int_eq(kty, JWK_KEY_TYPE_EC);

	/* Check bits */
	bits = jwks_item_key_bits(g_item);
	ck_assert_int_eq(bits, 384);

	/* Check that these aren't there */
	ret = jwks_item_key_oct(g_item, &buf, &len);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_null(buf);
	ck_assert_int_eq(len, 0);

	/* Pub key will fail to set */
	ret = jwt_builder_setkey(builder, JWT_ALG_ES384, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			 "Signing requires a private key");

	free_key();
}
END_TEST

static int __gen_hs256_wcb(jwt_t *jwt, jwt_config_t *config)
{
	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);
	ck_assert_int_eq(jwt_get_alg(jwt), JWT_ALG_NONE);

	if (config->ctx != NULL) {
		ck_assert_int_eq(jwt_get_alg(jwt), JWT_ALG_NONE);
		config->key = g_item;
		config->alg = JWT_ALG_HS256;
	} else {
		config->key = NULL;
		config->alg = JWT_ALG_HS256;
	}

	return 0;
}

START_TEST(gen_hs256_wcb)
{
	jwt_builder_auto_t *builder = NULL;
	char *out = NULL;
	const char exp[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");

	ret = jwt_builder_setcb(builder, __gen_hs256_wcb, "testing");
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);
	free(out);

	ret = jwt_builder_setcb(builder, __gen_hs256_wcb, NULL);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_int_eq(jwt_builder_error(builder), 1);

	free_key();
}
END_TEST

START_TEST(gen_hs256_stress)
{
	jwt_builder_auto_t *builder = NULL;
	const char exp[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret, i;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	for (i = 0; i < 1000; i++) {
		char_auto *out = jwt_builder_generate(builder);
		ck_assert_ptr_nonnull(out);
		ck_assert_str_eq(out, exp);
	}

	free_key();
}
END_TEST

START_TEST(claim_str_addgetdel)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJteS1mcmllbmQifQ.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "my-friend");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "aud", "public");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "aud", "private");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_STR(&jval, "aud", "employees");
	jval.replace = 1;
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "aud");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "employees");

	jwt_set_GET_INT(&jval, "aud");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_BOOL(&jval, "aud");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_builder_claim_del(builder, "aud");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "aud");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);
}
END_TEST

START_TEST(claim_int_addgetdel)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJuYmYiOjE0NzU5ODA1NDV9.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "nbf", TS_CONST);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST + 360);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST + 480);
	jval.replace = 1;
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "exp");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jval.int_val, TS_CONST + 480);

	jwt_set_GET_STR(&jval, "exp");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_BOOL(&jval, "exp");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_builder_claim_del(builder, "exp");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "exp");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);
}
END_TEST

START_TEST(claim_bool_addgetdel)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "admin", 1);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "sudo", 1);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "sudo", 0);
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_BOOL(&jval, "sudo", 0);
	jval.replace = 1;
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "sudo");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jval.bool_val, 0);

	jwt_set_GET_STR(&jval, "sudo");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_INT(&jval, "sudo");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_builder_claim_del(builder, "sudo");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "sudo");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);
}
END_TEST

START_TEST(claim_json_addgetdel)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJyb29tcyI6WyJvZ"
		"mZpY2UiLCJ3YXItcm9vbSJdfQ.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_JSON(&jval, "rooms",
			 "[\"office\",\"war-room\"]");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "rooms");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "[\"office\",\"war-room\"]");
	free(jval.json_val);

	jwt_set_ADD_JSON(&jval, "buildings",
			 "{\"main\":\"dallas\",\"accounting\":\"houston\"}");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_JSON(&jval, "buildings", "{\"hq\": 0}");
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_JSON(&jval, "buildings", "{\"hq\": 1}");
	jval.replace = 1;
	ret = jwt_builder_claim_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "buildings");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "{\"hq\":1}");
	free(jval.json_val);

	jwt_set_GET_STR(&jval, "buildings");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_INT(&jval, "buildings");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_builder_claim_del(builder, "buildings");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "buildings");
	ret = jwt_builder_claim_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);
}
END_TEST

START_TEST(header_str_addgetdel)
{
	const char exp[] = "eyJhbGciOiJub25lIiwidHlwIjoiQ3VzdG9tIn0.e30.";
	jwt_builder_auto_t *builder = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_setclaims(builder, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "typ", "Custom");
	ret = jwt_builder_header_add(builder, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, exp);

	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_builder_header_get(builder, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "Custom");

	ret = jwt_builder_header_del(builder, "typ");

	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_builder_header_get(builder, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("New");
	tcase_add_loop_test(tc_core, new, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Gen");
	tcase_add_loop_test(tc_core, gen, 0, i);
	tcase_add_loop_test(tc_core, gen_stress, 0, i);
	tcase_add_loop_test(tc_core, gen_wcb, 0, i);
	tcase_add_loop_test(tc_core, gen_es384_pub, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Error Handling");
	tcase_add_loop_test(tc_core, null_handling, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("HS256 Key Gen");
	tcase_add_loop_test(tc_core, gen_hs256, 0, i);
	tcase_add_loop_test(tc_core, gen_hs256_bits, 0, i);
	tcase_add_loop_test(tc_core, gen_hs256_wcb, 0, i);
	tcase_add_loop_test(tc_core, gen_hs256_stress, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Claims AddGetDel");
	tcase_add_loop_test(tc_core, claim_str_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_int_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_bool_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_json_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claims_set_errors, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Header AddGetDel");
	/* All of the code paths for str/int/bool/json have been covered. We
	 * just run this to ensure add/get/del works on headers */
	tcase_add_loop_test(tc_core, header_str_addgetdel, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Builder");
}
