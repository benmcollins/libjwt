/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7516,11.4} Key-usage gating is exercised through the public
 * jwe_builder_setkey / jwe_checker_setkey, which call the internal
 * jwe_key_usage_check. The builder is the producer (wrap/encrypt), the
 * checker the consumer (unwrap/decrypt). */

START_TEST(oct_no_restrictions)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* oct_key_256.json has no "use"/"key_ops" -> usable for A*KW/dir. */
	read_json("oct_key_256.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwe_builder_setkey(builder, JWE_ALG_DIR, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(oct_use_enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	/* use:enc, key_ops:[wrapKey,unwrapKey] */
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(oct_use_sig_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* use:sig must never be usable for JWE. */
	read_json("oct_key_256_sig.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_int_eq(jwe_builder_error(builder), 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key marked for signing cannot be used for JWE");

	free_key();
}
END_TEST

START_TEST(oct_key_ops_direction)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	/* key_ops:[wrapKey] only: builder (wrap) OK, checker (unwrap) rejected. */
	read_json("oct_key_256_wrap_only.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_checker_error_msg(checker),
			 "Key does not permit the required JWE operation");

	free_key();
}
END_TEST

START_TEST(wrong_kty_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* An RSA key cannot be used for AES Key Wrap (needs oct). */
	read_json("rsa_key_2048.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key type does not match JWE algorithm");

	free_key();
}
END_TEST

START_TEST(rsa_oaep_kty)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* use:enc RSA key is valid for RSA-OAEP. */
	read_json("rsa_key_2048_enc.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP_256, JWE_ENC_A128GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(rsa_sig_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* The stock RSA test key is use:sig and must be rejected for JWE. */
	read_json("rsa_key_2048.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key marked for signing cannot be used for JWE");

	free_key();

	/* An oct key cannot be used for RSA-OAEP regardless of usage. */
	read_json("oct_key_256.json");
	jwe_builder_error_clear(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key type does not match JWE algorithm");

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE Key Usage");

	tcase_add_loop_test(tc_core, oct_no_restrictions, 0, i);
	tcase_add_loop_test(tc_core, oct_use_enc, 0, i);
	tcase_add_loop_test(tc_core, oct_use_sig_rejected, 0, i);
	tcase_add_loop_test(tc_core, oct_key_ops_direction, 0, i);
	tcase_add_loop_test(tc_core, wrong_kty_rejected, 0, i);
	tcase_add_loop_test(tc_core, rsa_oaep_kty, 0, i);
	tcase_add_loop_test(tc_core, rsa_sig_rejected, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE Key Usage");
}
