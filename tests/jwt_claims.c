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
	time_t tm;
	int ret;

	SET_OPS();

	__get_set(&builder, &checker);

	/* Set nbf +10 */
	ret = jwt_builder_time_offset_set(builder, JWT_CLAIM_NBF, 10);
	ck_assert_int_eq(ret, 0);
	tm = jwt_builder_time_offset_get(builder, JWT_CLAIM_NBF);
	ck_assert_int_eq(tm, 10);

	/* Gen with "nbf" claim */
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* Small leeway */
	ret = jwt_checker_leeway_set(checker, JWT_CLAIM_NBF, 1);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_checker_leeway_get(checker, JWT_CLAIM_NBF);;
	ck_assert_int_eq(tm, 1);

	/* Too soon */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
	jwt_checker_error_clear(checker);

	/* Bigger leeway */
	ret = jwt_checker_leeway_set(checker, JWT_CLAIM_NBF, 10);;
	ck_assert_int_eq(ret, 0);

	/* Should pass */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	/* We clear the check */
	ret = jwt_checker_leeway_clear(checker, JWT_CLAIM_NBF);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_checker_leeway_get(checker, JWT_CLAIM_NBF);;
	ck_assert_int_eq(tm, 0);

	/* We clear the check */
        ret = jwt_builder_time_offset_clear(builder, JWT_CLAIM_NBF);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_builder_time_offset_get(builder, JWT_CLAIM_NBF);;
	ck_assert_int_eq(tm, 0);

	free(out);
	free_key();
}
END_TEST

START_TEST(claims_exp_leeway)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char *out = NULL;
	time_t tm;
	int ret;

	SET_OPS();

	__get_set(&builder, &checker);

	/* Set exp -2 */
	ret = jwt_builder_time_offset_set(builder, JWT_CLAIM_EXP, -2);
	ck_assert_int_eq(ret, 0);
	tm = jwt_builder_time_offset_get(builder, JWT_CLAIM_EXP);
	ck_assert_int_eq(tm, -2);

	/* Gen with "exp" claim */
	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* Small leeway */
	ret = jwt_checker_leeway_set(checker, JWT_CLAIM_EXP, 1);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_checker_leeway_get(checker, JWT_CLAIM_EXP);;
	ck_assert_int_eq(tm, 1);

	/* Too late */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
	                "Failed one or more claims");
	jwt_checker_error_clear(checker);

	/* Bigger leeway */
	ret = jwt_checker_leeway_set(checker, JWT_CLAIM_EXP, 10);;
	ck_assert_int_eq(ret, 0);

	/* Should pass */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	/* We clear the check */
	ret = jwt_checker_leeway_clear(checker, JWT_CLAIM_EXP);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_checker_leeway_get(checker, JWT_CLAIM_EXP);;
	ck_assert_int_eq(tm, 0);

	/* We clear the check */
        ret = jwt_builder_time_offset_clear(builder, JWT_CLAIM_EXP);;
	ck_assert_int_eq(ret, 0);
	tm = jwt_builder_time_offset_get(builder, JWT_CLAIM_EXP);;
	ck_assert_int_eq(tm, 0);

	free(out);
	free_key();
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
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Claims Handling");
}
