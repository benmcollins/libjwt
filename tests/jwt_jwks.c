/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

#define JWKS_KEY_TEST(__name)				\
START_TEST(test_jwks_##__name)				\
{							\
	SET_OPS_JWK();					\
       __jwks_check(#__name ".json", #__name ".pem");	\
}							\
END_TEST

static void __jwks_check(const char *json, const char *pem)
{
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	int strcmp_ret;

	read_key(json);
	jwk_set = jwks_create((char *)key);
	free_key();
	ck_assert_ptr_nonnull(jwk_set);

	ck_assert(!jwks_error(jwk_set));
	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert(!item->error);

	read_key(pem);
	strcmp_ret = strcmp(item->pem, (char *)key);
	free_key();
	ck_assert_int_eq(strcmp_ret, 0);

	item = jwks_item_get(jwk_set, 1);
	ck_assert_ptr_null(item);

        jwks_free(jwk_set);
}

JWKS_KEY_TEST(ec_key_prime256v1);
JWKS_KEY_TEST(ec_key_prime256v1_pub);
JWKS_KEY_TEST(ec_key_secp256k1);
JWKS_KEY_TEST(ec_key_secp256k1_pub);
JWKS_KEY_TEST(ec_key_secp384r1);
JWKS_KEY_TEST(ec_key_secp384r1_pub);
JWKS_KEY_TEST(ec_key_secp521r1);
JWKS_KEY_TEST(ec_key_secp521r1_pub);
JWKS_KEY_TEST(eddsa_key_ed25519);
JWKS_KEY_TEST(eddsa_key_ed25519_pub);
JWKS_KEY_TEST(rsa_key_2048);
JWKS_KEY_TEST(rsa_key_2048_pub);
JWKS_KEY_TEST(rsa_key_4096);
JWKS_KEY_TEST(rsa_key_4096_pub);
JWKS_KEY_TEST(rsa_key_8192);
JWKS_KEY_TEST(rsa_key_8192_pub);
JWKS_KEY_TEST(rsa_key_i37_pub);
JWKS_KEY_TEST(rsa_pss_key_2048);
JWKS_KEY_TEST(rsa_pss_key_2048_pub);

START_TEST(test_jwks_keyring_load)
{
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	int i;

	SET_OPS_JWK();

	read_key("jwks_keyring.json");
	jwk_set = jwks_create((char *)key);
	free_key();

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	for (i = 0; (item = jwks_item_get(jwk_set, i)); i++)
		ck_assert(!item->error);

	ck_assert_int_eq(i, 19);

	ck_assert(jwks_item_free(jwk_set, 3));

	jwks_free(jwk_set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks");

	tcase_add_loop_test(tc_core, test_jwks_ec_key_prime256v1, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_prime256v1_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp256k1, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp256k1_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp384r1, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp384r1_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp521r1, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_ec_key_secp521r1_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_eddsa_key_ed25519, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_eddsa_key_ed25519_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_2048, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_2048_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_4096, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_4096_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_8192, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_8192_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_key_i37_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_pss_key_2048, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_rsa_pss_key_2048_pub, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_keyring_load, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT JWKS");
}
