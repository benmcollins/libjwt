/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

#include <openssl/opensslconf.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define openssl_check()
#else
#define openssl_check() return;
#endif

START_TEST(test_jwks_rsa_pub_missing)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\"}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	const char exp[] = "Missing required RSA component: n or e";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(item->error, 0);

	ck_assert_str_eq(exp, item->error_msg);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_rsa_pub_bad_type)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\",\"e\":1}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	const char exp[] = "Error decoding pub components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(item->error, 0);

	ck_assert_str_eq(exp, item->error_msg);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_rsa_pub_bad64)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\",\"n\":\"\",\"e\":\"asaadaaaaaa\"}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	const char exp[] = "Error decoding pub components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(item->error, 0);

	ck_assert_str_eq(exp, item->error_msg);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_rsa_pub_binary64)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\",\"n\":"
		"\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\","
		"\"e\":\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\"}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_ptr_nonnull(item->pem);
	ck_assert_int_eq(item->error, 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_rsa_priv_missing)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\","
		"\"e\":\"YmFkdmFsdWUK\",\"d\":\"YmFkdmFsdWUK\"}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	const char exp[] = "Some priv key components exist, but some are missing";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(item->error, 0);

	ck_assert_str_eq(exp, item->error_msg);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_rsa_priv_bad64)
{ openssl_check();
	const char *json = "{\"kty\":\"RSA\",\"n\":\"YmFkdmFsdWUK\","
		"\"e\":\"YmFkdmFsdWUK\",\"d\":"
		"\"2fyxRFHaYP2a4pbdTK/s9x4YWV7qAWwJMXMkbRmy51w\","
		"\"p\":\"\",\"q\":\"=\",\"dp\":\"\",\"dq\":\"\",\"qi\":\"\"}";
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	const char exp[] = "Error decoding priv components";

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(item->error, 0);

	ck_assert_str_eq(exp, item->error_msg);

	jwks_free(jwk_set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops) - 1;

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_rsa");

	/* RSA specific error path tests */
	tcase_add_loop_test(tc_core, test_jwks_rsa_pub_missing, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_pub_bad64, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_pub_bad_type, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_pub_binary64, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_priv_missing, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_priv_bad64, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing RSA");
}
