/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"

static void __verify_token(const char *token, jwt_alg_t alg)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setkey(checker, alg, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}

static void __test_alg(const char *key_file, jwt_alg_t alg, const char *expected)
{
	jwt_builder_auto_t *builder = NULL;
	const unsigned char *buf = NULL;
	char *out = NULL;
	size_t len = 0;
	int ret;

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	ret = jwt_builder_enable_iat(builder, 0);
	ck_assert_int_eq(ret, 1);

	read_json(key_file);
	ret = jwt_builder_setkey(builder, alg, g_item);
	ck_assert_int_eq(ret, 0);

	/* Check the values */
	ret = jwks_item_key_oct(g_item, &buf, &len);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(buf);
	ck_assert_int_ge(len, 32);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, expected);

	__verify_token(out, alg);

	free(out);

	free_key();
}

START_TEST(hs_too_small)
{
	jwt_builder_auto_t *builder = NULL;
	int ret;
	const char *out = NULL;

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	read_json("oct_key_128_too_small.json");

	ret = jwt_builder_setkey(builder, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);
	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);

	ret = jwt_builder_setkey(builder, JWT_ALG_HS384, g_item);
	ck_assert_int_eq(ret, 0);
	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);

	ret = jwt_builder_setkey(builder, JWT_ALG_HS512, g_item);
	ck_assert_int_eq(ret, 0);
	out = jwt_builder_generate(builder);
	ck_assert_ptr_null(out);
}
END_TEST

START_TEST(hs256)
{
	const char exp[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";

	SET_OPS();

	__test_alg("oct_key_256.json", JWT_ALG_HS256, exp);
}
END_TEST

START_TEST(hs384)
{
	const char exp[] = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.GKapA5V0"
		"PiRn-pNHK1Vj-E01pYv1Gx0VOkzzgp-SbfWQaOz6q6MiiCyVM0P69idm";

	SET_OPS();

	__test_alg("oct_key_384.json", JWT_ALG_HS384, exp);
}
END_TEST

START_TEST(hs512)
{
	const char exp[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.yeSPkrpAm"
		"_6UGtg2SpdPUV0tsrhVosfxKLuUIqMRwhEEyg6jAWe4J-qKiPdJZfC1MVeMwk"
		"zwB_k-o9RDi_gSbA";

	SET_OPS();

	__test_alg("oct_key_512.json", JWT_ALG_HS512, exp);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("HS Key Gen/Ver");
	tcase_add_loop_test(tc_core, hs256, 0, i);
	tcase_add_loop_test(tc_core, hs384, 0, i);
	tcase_add_loop_test(tc_core, hs512, 0, i);
	tcase_add_loop_test(tc_core, hs_too_small, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT HMAC Algorithms");
}
