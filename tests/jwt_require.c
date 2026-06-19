/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for jwt_checker_require(): assert a set of claims is PRESENT in a token,
 * independent of any value match (the RFC 9068 mandatory-claims discipline). A
 * token is built with iss/aud/sub/client_id/iat/exp but NO jti; requiring a
 * present set verifies, requiring an absent claim (jti) is rejected. */

static jwk_set_t *load_key(void)
{
	jwk_set_t *set = jwks_create_fromfile(KEYDIR "/ec_key_prime256v1.json");

	ck_assert_ptr_nonnull(set);
	return set;
}

/* An ES256 token carrying iss/aud/sub/client_id/iat/exp, optionally jti. */
static char *make_token(const jwk_item_t *key, int with_jti)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);

	jwt_set_SET_STR(&v, "iss", "https://issuer.example");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	jwt_set_SET_STR(&v, "aud", "https://api.example");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	jwt_set_SET_STR(&v, "sub", "user-1");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	jwt_set_SET_STR(&v, "client_id", "client-42");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	if (with_jti) {
		jwt_set_SET_STR(&v, "jti", "id-1");
		ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	}

	/* A future exp (an int claim, to prove presence is type-agnostic). */
	ck_assert_int_eq(jwt_builder_time_offset(b, JWT_CLAIM_EXP, 3600), 0);

	return jwt_builder_generate(b);
}

START_TEST(test_require_present)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	const char *names[] = { "iss", "exp", "aud", "sub", "client_id", "iat" };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	token = make_token(key, 0);
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_require(checker, names, ARRAY_SIZE(names)), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

START_TEST(test_require_missing_rejected)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	const char *names[] = { "iss", "jti" };	/* jti is absent */

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	token = make_token(key, 0);
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_require(checker, names, ARRAY_SIZE(names)), 0);
	ck_assert_int_ne(jwt_checker_verify(checker, token), 0);
	/* The error names the missing claim. */
	ck_assert_ptr_nonnull(strstr(jwt_checker_error_msg(checker), "jti"));

	jwks_free(set);
}
END_TEST

START_TEST(test_require_present_with_jti)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	const char *names[] = { "jti" };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	token = make_token(key, 1);	/* with jti */
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_require(checker, names, ARRAY_SIZE(names)), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

START_TEST(test_require_clear)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	const char *names[] = { "jti" };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	token = make_token(key, 0);	/* no jti */
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, key), 0);

	/* Require jti, then clear the requirement: the absent jti no longer fails. */
	ck_assert_int_eq(jwt_checker_require(checker, names, 1), 0);
	ck_assert_int_eq(jwt_checker_require(checker, NULL, 0), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

START_TEST(test_require_errors)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	const char *good[] = { "iss" };
	const char *bad[] = { "iss", "" };	/* empty name */

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	token = make_token(key, 0);
	ck_assert_ptr_nonnull(token);

	ck_assert_int_ne(jwt_checker_require(NULL, good, 1), 0);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, key), 0);

	/* An empty name in the list is rejected and leaves no requirement set. */
	ck_assert_int_ne(jwt_checker_require(checker, bad, ARRAY_SIZE(bad)), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_require");

	tcase_add_loop_test(tc_core, test_require_present, 0, i);
	tcase_add_loop_test(tc_core, test_require_missing_rejected, 0, i);
	tcase_add_loop_test(tc_core, test_require_present_with_jti, 0, i);
	tcase_add_loop_test(tc_core, test_require_clear, 0, i);
	tcase_add_loop_test(tc_core, test_require_errors, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT required-claims (jwt_checker_require)");
}
