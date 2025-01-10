/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwks_ec_pub_missing)
{
	const char *json = "{\"kty\":\"EC\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Missing or invalid type for one of crv, x, or y for pub key";

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

START_TEST(test_jwks_ec_pub_bad_type)
{
	const char *json = "{\"kty\":\"EC\",\"crv\":\"prime6v1\",\"x\":\"sd+#(@#($(ada\",\"y\":1}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Missing or invalid type for one of crv, x, or y for pub key";

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

START_TEST(test_jwks_ec_pub_bad64)
{
	const char *json = "{\"kty\":\"EC\",\"crv\":\"prime6v1\",\"x\":\"\",\"y\":\"asaad\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Error generating pub key from components";

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

START_TEST(test_jwks_ec_pub_bad_points)
{
	const char *json = "{\"kty\":\"EC\",\"crv\":\"prime256v1\",\"x\":\"YmFkdmFsdWUK\",\"y\":\"YmFkdmFsdWUK\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Error generating pub key from components";

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

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_ec");

	/* EC specific error path tests */
	tcase_add_loop_test(tc_core, test_jwks_ec_pub_missing, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_pub_bad64, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_pub_bad_type, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_pub_bad_points, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing EC");
}
