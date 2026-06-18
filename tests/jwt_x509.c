/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7517,4.7,4.8,4.9} X.509 JWK parameters x5c / x5t / x5t#S256 (issue #314,
 * phase 1). Runs under each crypto backend (SET_OPS) and both JSON backends. */

static jwk_set_t *load(const char *file)
{
	char *path;
	jwk_set_t *set;
	int ret;

	ret = asprintf(&path, KEYDIR "/%s", file);
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

/* A JWK with an x5c chain and a matching x5t#S256 parses cleanly and exposes
 * the DER leaf + thumbprints. */
START_TEST(test_x5c_parse)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	const unsigned char *der;
	size_t der_len = 0;

	SET_OPS();
	set = load("ec_key_with_x5c.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);

	/* One cert in the chain; the leaf is real DER (SEQUENCE tag 0x30). */
	ck_assert_uint_eq(jwks_item_x5c_count(item), 1);
	der = jwks_item_x5c(item, 0, &der_len);
	ck_assert_ptr_nonnull(der);
	ck_assert_uint_gt(der_len, 0);
	ck_assert_int_eq(der[0], 0x30);

	/* Out-of-range index returns NULL. */
	ck_assert_ptr_null(jwks_item_x5c(item, 1, &der_len));

	/* x5t#S256 is present (and was validated against the leaf at parse). */
	ck_assert_ptr_nonnull(jwks_item_x5t_s256(item));
	/* This fixture has no legacy x5t. */
	ck_assert_ptr_null(jwks_item_x5t(item));

	jwks_free(set);
}
END_TEST

/* A JWK whose x5t#S256 disagrees with its x5c leaf is rejected (RFC 7517 4.9). */
START_TEST(test_x5t_mismatch)
{
	jwk_set_t *set;
	const jwk_item_t *item;

	SET_OPS();
	set = load("ec_key_x5c_bad_x5t.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 1);
	ck_assert_ptr_nonnull(strstr(jwks_item_error_msg(item), "x5t#S256"));

	jwks_free(set);
}
END_TEST

/* A JWK with no X.509 parameters exposes none. */
START_TEST(test_no_x5c)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	size_t len = 99;

	SET_OPS();
	set = load("ec_key_prime256v1_pub.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);

	ck_assert_uint_eq(jwks_item_x5c_count(item), 0);
	ck_assert_ptr_null(jwks_item_x5c(item, 0, &len));
	ck_assert_ptr_null(jwks_item_x5t(item));
	ck_assert_ptr_null(jwks_item_x5t_s256(item));

	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_x509");

	tcase_add_loop_test(tc_core, test_x5c_parse, 0, i);
	tcase_add_loop_test(tc_core, test_x5t_mismatch, 0, i);
	tcase_add_loop_test(tc_core, test_no_x5c, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT X.509 JWK params x5c/x5t/x5t#S256 (#314)");
}
