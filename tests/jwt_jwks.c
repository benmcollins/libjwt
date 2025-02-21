/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwks_keyring_load)
{
	const jwk_item_t *item;
	int i, ret;
	int fails = 0;

	SET_OPS();

	read_json("jwks_keyring.json");

	for (i = 0; (item = jwks_item_get(g_jwk_set, i)); i++) {
		jwt_builder_auto_t *builder = NULL;
		char_auto *out = NULL;
		jwt_alg_t alg;

		if (jwks_item_error(item)) {
			fprintf(stderr, "Err KID: %s\n",
				jwks_item_kid(item));
		}
		ck_assert_int_eq(jwks_item_error(item), 0);

		alg = jwks_item_alg(item);

		if (alg == JWT_ALG_ES256K)
			continue;

		if (alg == JWT_ALG_NONE || !jwks_item_is_private(item))
			continue;

		builder = jwt_builder_new();
		ck_assert_ptr_nonnull(builder);

		ret = jwt_builder_setkey(builder, alg, item);
		ck_assert_int_eq(ret, 0);

		out = jwt_builder_generate(builder);
		if (out == NULL) {
			fprintf(stderr, "Gen KID(%d/%s): %s\n", i,
				jwt_alg_str(alg),
				jwt_builder_error_msg(builder));
			fails++;
		}
	}
	ck_assert_int_eq(fails, 0);

	item = jwks_find_bykid(g_jwk_set, "SDSDS");
	ck_assert_ptr_null(item);

	item = jwks_find_bykid(g_jwk_set, "354912a0-b90a-435e-886a-1629f7b2665e");
	ck_assert_ptr_nonnull(item);

	ck_assert_int_eq(i, 27);
	i = jwks_item_count(g_jwk_set);
	ck_assert_int_eq(i, 27);

	ck_assert(jwks_item_free(g_jwk_set, 3));

	i = jwks_item_count(g_jwk_set);
	ck_assert_int_eq(i, 26);

	i = jwks_item_free_bad(g_jwk_set);
	ck_assert_int_eq(i, 0);

	i = jwks_item_count(g_jwk_set);
	ck_assert_int_eq(i, 26);

	free_key();
}
END_TEST

#ifdef HAVE_LIBCURL
START_TEST(load_fromurl)
{
	jwk_set_auto_t *jwk_set = NULL;
	const char *test_url = getenv("LIBJWT_TEST_URL");
	char *check;

	SET_OPS();

	jwk_set = jwks_create_fromurl(NULL, 1);
	ck_assert_ptr_null(jwk_set);

	jwk_set = jwks_create_fromurl("file:///DOESNOTEXIST", 1);
	ck_assert_ptr_nonnull(jwk_set);
	check = strstr(jwks_error_msg(jwk_set), "read a file:// file");
	ck_assert_ptr_nonnull(check);
	jwks_error_clear(jwk_set);

	jwk_set = jwks_load_fromurl(jwk_set, "https://127.0.0.1:8989", 1);
	ck_assert_ptr_nonnull(jwk_set);
	check = strstr(jwks_error_msg(jwk_set), "connect to server");
	ck_assert_ptr_nonnull(check);
	jwks_error_clear(jwk_set);

	if (test_url == NULL || !strlen(test_url))
		test_url = "file://" KEYDIR "/jwks_keyring.json";

	jwk_set = jwks_load_fromurl(jwk_set, test_url, 2);
	ck_assert_ptr_nonnull(jwk_set);

	ck_assert_int_gt(jwks_item_count(jwk_set), 0);
}
#else
START_TEST(load_fromurl)
{
	ck_assert_ptr_null(jwks_create_fromurl("file:///", 1));
}
END_TEST
#endif

START_TEST(test_jwks_keyring_all_bad)
{
	const jwk_item_t *item;
	jwk_set_auto_t *jwk_set;
	int i;

        SET_OPS();

	jwk_set = jwks_create_fromfile(KEYDIR "/bad_keys.json");
	ck_assert_ptr_nonnull(jwk_set);

	i = jwks_error_any(jwk_set);
	ck_assert_int_eq(i, 14);

	for (i = 0; (item = jwks_item_get(jwk_set, i)); i++) {
		if (!jwks_item_error(item)) {
			fprintf(stderr, "KID: %s\n",
				jwks_item_kid(item));
		}
		ck_assert_int_ne(jwks_item_error(item), 0);
	}

	ck_assert_int_eq(i, 14);

	i = jwks_item_free_bad(jwk_set);
	ck_assert_int_eq(i, 14);

	i = jwks_item_count(jwk_set);
	ck_assert_int_eq(i, 0);
}
END_TEST

START_TEST(test_jwks_key_op_all_types)
{
	jwk_key_op_t key_ops = JWK_KEY_OP_SIGN | JWK_KEY_OP_VERIFY |
		JWK_KEY_OP_ENCRYPT | JWK_KEY_OP_DECRYPT | JWK_KEY_OP_WRAP |
		JWK_KEY_OP_UNWRAP | JWK_KEY_OP_DERIVE_KEY |
		JWK_KEY_OP_DERIVE_BITS;

	const jwk_item_t *item;

	SET_OPS();

	read_jsonfp("jwks_test-1.json");

	item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert(!jwks_item_error(item));

	ck_assert_int_eq(jwks_item_key_ops(item), key_ops);

	free_key();
}
END_TEST

START_TEST(test_jwks_key_op_bad_type)
{
	const jwk_item_t *item;
	const char *kid = "264265c2-4ef0-4751-adbd-9739550afe5b";

	SET_OPS();

	read_json("jwks_test-2.json");

	item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(item);

	/* The bad key_op is ignored. */
	ck_assert(!jwks_item_error(item));

	/* Only these ops set. */
	ck_assert_int_eq(jwks_item_key_ops(item),
		JWK_KEY_OP_VERIFY | JWK_KEY_OP_DERIVE_BITS);

	ck_assert_int_eq(jwks_item_use(item), JWK_PUB_KEY_USE_ENC);

	/* Check this key ID. */
	ck_assert_str_eq(jwks_item_kid(item), kid);

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks");

	/* Load a whole keyring */
	tcase_add_loop_test(tc_core, test_jwks_keyring_load, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_keyring_all_bad, 0, i);

	tcase_add_loop_test(tc_core, load_fromurl, 0, i);

	/* Some coverage attempts */
	tcase_add_loop_test(tc_core, test_jwks_key_op_all_types, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_key_op_bad_type, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS");
}
