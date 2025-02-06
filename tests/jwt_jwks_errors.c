/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwks_bad_json)
{
	const char *json = "INVALID";
	jwk_set_t *jwk_set = NULL;
	const char *msg;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(jwks_error(jwk_set));

	msg = jwks_error_msg(jwk_set);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(msg[0] != '\0');

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_unknown_kty)
{
	const char *json = "{\"kty\":\"INVALID\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Unknown or unsupported kty type";
	int ret;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ret = strncmp(exp, jwks_item_error_msg(item), strlen(exp));
	ck_assert_int_eq(ret, 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_missing_kty)
{
	const char *json = "{\"NOT-kty\":\"INVALID\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Invalid JWK: missing kty value";
	int ret;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ret = strncmp(exp, jwks_item_error_msg(item), strlen(exp));
	ck_assert_int_eq(ret, 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_empty)
{
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	int ret;

	SET_OPS();

	jwk_set = jwks_create(NULL);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_null(item);

	/* Try some null things */
	ret = jwks_item_free(NULL, 0);
	ck_assert_int_eq(ret, 0);

	ret = jwks_item_free_all(NULL);
	ck_assert_int_eq(ret, 0);

	jwks_free(NULL);

	ck_assert_ptr_null(jwks_create_strn(NULL, 0));

	ck_assert_ptr_null(jwks_create_fromfile(NULL));

	ck_assert_ptr_null(jwks_create_fromfp(NULL));

	jwks_free(jwk_set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_errors");

	/* Core JWKS Error path tests */
	tcase_add_loop_test(tc_core, test_jwks_bad_json, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_empty, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_unknown_kty, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_missing_kty, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing");
}
