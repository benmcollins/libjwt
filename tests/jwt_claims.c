/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"

static void __get_set(jwt_builder_t **builder, jwt_checker_t **checker)
{
	int ret;

	read_json("oct_key_256.json");

	/* One to build */
	*builder = jwt_builder_new();
	ck_assert_ptr_nonnull(*builder);
	ck_assert_int_eq(jwt_builder_error(*builder), 0);

	/* One to check */
	*checker = jwt_checker_new();
	ck_assert_ptr_nonnull(*checker);
	ck_assert_int_eq(jwt_checker_error(*checker), 0);

	/* Set the same key for both */
	ret = jwt_builder_setkey(*builder, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_setkey(*checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);
}

START_TEST(claims_nbf_leeway)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char *out = NULL;
	int ret;

	SET_OPS();

	__get_set(&builder, &checker);

	/* Set nbf +10 */
	ret = jwt_builder_time_offset(builder, JWT_CLAIM_NBF, 10);
	ck_assert_int_eq(ret, 0);

	/* Gen with "nbf" claim */
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* Small leeway */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, 1);;
	ck_assert_int_eq(ret, 0);

	/* Too soon */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
	jwt_checker_error_clear(checker);

	/* Bigger leeway */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, 10);;
	ck_assert_int_eq(ret, 0);

	/* Should pass */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	/* We clear the check */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1);
	ck_assert_int_eq(ret, 0);

	/* Should pass */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	free(out);
	free_key();
}
END_TEST

START_TEST(claims_exp_leeway)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char *out = NULL;
	int ret;

	SET_OPS();

	__get_set(&builder, &checker);

	/* Set exp */
	ret = jwt_builder_time_offset(builder, JWT_CLAIM_EXP, 1);
	ck_assert_int_eq(ret, 0);

	/* Gen with "exp" claim */
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* We gotta sleep for this to work */
	sleep(1);

	/* No leeway */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, 0);;
	ck_assert_int_eq(ret, 0);

	/* Too late */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
	                "Failed one or more claims");
	jwt_checker_error_clear(checker);

	/* Bigger leeway */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, 10);;
	ck_assert_int_eq(ret, 0);

	/* Should pass */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	/* We clear the check */
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1);;
	ck_assert_int_eq(ret, 0);

	free(out);
	free_key();
}
END_TEST

static void __test_claim(const char *cstr, jwt_claims_t claim)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	jwt_value_error_t jerr;
	jwt_value_t jval;
	char *out = NULL;
	int ret;

	__get_set(&builder, &checker);

	/* Gen with claim */
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* Set what to expect */
	ret = jwt_checker_claim_set(checker, claim, "foo.example.com");;
	ck_assert_int_eq(ret, 0);

	/* Should fail, because it's missing */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);

	/* Set claim string */
	jwt_set_SET_STR(&jval, cstr, "disk.swissdisk.com");
	jerr = jwt_builder_claim_set(builder, &jval);
	ck_assert_int_eq(jerr, JWT_VALUE_ERR_NONE);

	/* Gen new with claim set */
	free(out);
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* Should fail, because of mismatch */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);

	free(out);
	free_key();
}

START_TEST(claims_iss)
{
	SET_OPS();

	__test_claim("iss", JWT_CLAIM_ISS);
}
END_TEST

START_TEST(claims_aud)
{
	SET_OPS();

	__test_claim("aud", JWT_CLAIM_AUD);
}
END_TEST

START_TEST(claims_sub)
{
	SET_OPS();

	__test_claim("sub", JWT_CLAIM_SUB);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("Claims Build/Check");
	tcase_add_loop_test(tc_core, claims_nbf_leeway, 0, i);
	tcase_add_loop_test(tc_core, claims_exp_leeway, 0, i);
	tcase_add_loop_test(tc_core, claims_iss, 0, i);
	tcase_add_loop_test(tc_core, claims_aud, 0, i);
	tcase_add_loop_test(tc_core, claims_sub, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Claims Handling");
}
