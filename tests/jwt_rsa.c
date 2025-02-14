/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(rsa_pub_missing)
{
	const char *json = "{\"kty\":\"RSA\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Missing required RSA component: n or e";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ck_assert_str_eq(exp, jwks_item_error_msg(item));

	jwks_free(jwk_set);
}
END_TEST


START_TEST(rsa_pub_bad_type)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\",\"e\":1}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Error decoding pub components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ck_assert_str_eq(exp, jwks_item_error_msg(item));

	jwks_free(jwk_set);
}
END_TEST

START_TEST(rsa_pub_bad64)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":\"\",\"e\":\"asaadaaaaaa\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Error decoding pub components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ck_assert_str_eq(exp, jwks_item_error_msg(item));

	jwks_free(jwk_set);
}
END_TEST

START_TEST(rsa_pub_binary64)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":"
		"\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\","
		"\"e\":\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_ptr_nonnull(jwks_item_pem(item));
	ck_assert_int_eq(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(rsa_priv_missing)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\","
		"\"e\":\"YmFkdmFsdWUK\",\"d\":\"YmFkdmFsdWUK\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Some priv key components exist, but some are missing";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ck_assert_str_eq(exp, jwks_item_error_msg(item));

	jwks_free(jwk_set);
}
END_TEST

START_TEST(rsa_priv_bad64)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\","
		"\"e\":\"YmFkdmFsdWUK\",\"d\":"
		"\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\","
		"\"p\":\"\",\"q\":\"=\",\"dp\":\"\",\"dq\":\"\",\"qi\":\"\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Error decoding priv components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ck_assert_str_eq(exp, jwks_item_error_msg(item));

	jwks_free(jwk_set);
}
END_TEST

START_TEST(rsa_short)
{
	const char token[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI"
		"xMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlh"
		"dCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNb"
		"ftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn"
		"5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6X"
		"ETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E"
		"0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79Xd"
		"Iwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char *out = NULL;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	read_json("rsa_key_1024.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_RS256, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			"Key too short for RSA algs: 1024 bits");

	ret = jwt_builder_setkey(builder, JWT_ALG_RS256, g_item);
	ck_assert_int_eq(ret, 0);

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setkey(checker, JWT_ALG_RS256, g_item);
        ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Key too short for RSA algs: 1024 bits");

	free_key();
}
END_TEST

START_TEST(rsa_ec_short)
{
        jwt_builder_auto_t *builder = NULL;
        char *out = NULL;
        int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	read_json("rsa_key_1024.json");
	ret = jwt_builder_setkey(builder, JWT_ALG_ES256, g_item);
        ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			"Key needs to be 256 bits: 1024 bits");

	ret = jwt_builder_setkey(builder, JWT_ALG_EDDSA, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			"Key needs to be 256 or 456 bits: 1024 bits");

	ret = jwt_builder_setkey(builder, JWT_ALG_ES384, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			"Key needs to be 384 bits: 1024 bits");

	ret = jwt_builder_setkey(builder, JWT_ALG_ES512, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
	ck_assert_str_eq(jwt_builder_error_msg(builder),
			"Key needs to be 521 bits: 1024 bits");

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_rsa");

	/* RSA specific error path tests */
	tcase_add_loop_test(tc_core, rsa_pub_missing, 0, i);
	tcase_add_loop_test(tc_core, rsa_pub_bad64, 0, i);
	tcase_add_loop_test(tc_core, rsa_pub_bad_type, 0, i);
	tcase_add_loop_test(tc_core, rsa_pub_binary64, 0, i);
	tcase_add_loop_test(tc_core, rsa_priv_missing, 0, i);
	tcase_add_loop_test(tc_core, rsa_priv_bad64, 0, i);
	tcase_add_loop_test(tc_core, rsa_short, 0, i);
	tcase_add_loop_test(tc_core, rsa_ec_short, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing RSA");
}
