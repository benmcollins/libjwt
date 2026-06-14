/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Every defined jwe_key_alg_t value (excluding NONE/INVAL) with its string. */
static const struct {
	jwe_key_alg_t alg;
	const char *str;
} alg_map[] = {
	{ JWE_ALG_DIR,		"dir" },
	{ JWE_ALG_A128KW,	"A128KW" },
	{ JWE_ALG_A192KW,	"A192KW" },
	{ JWE_ALG_A256KW,	"A256KW" },
	{ JWE_ALG_RSA_OAEP,	"RSA-OAEP" },
	{ JWE_ALG_RSA_OAEP_256,	"RSA-OAEP-256" },
	{ JWE_ALG_ECDH_ES,	"ECDH-ES" },
	{ JWE_ALG_ECDH_ES_A128KW, "ECDH-ES+A128KW" },
	{ JWE_ALG_ECDH_ES_A192KW, "ECDH-ES+A192KW" },
	{ JWE_ALG_ECDH_ES_A256KW, "ECDH-ES+A256KW" },
};

/* Every defined jwe_enc_t value (excluding NONE/INVAL) with its string. */
static const struct {
	jwe_enc_t enc;
	const char *str;
} enc_map[] = {
	{ JWE_ENC_A128GCM,	"A128GCM" },
	{ JWE_ENC_A192GCM,	"A192GCM" },
	{ JWE_ENC_A256GCM,	"A256GCM" },
	{ JWE_ENC_A128CBC_HS256, "A128CBC-HS256" },
	{ JWE_ENC_A192CBC_HS384, "A192CBC-HS384" },
	{ JWE_ENC_A256CBC_HS512, "A256CBC-HS512" },
};

START_TEST(alg_roundtrip)
{
	size_t j;

	SET_OPS();

	for (j = 0; j < ARRAY_SIZE(alg_map); j++) {
		const char *s = jwe_alg_str(alg_map[j].alg);

		ck_assert_ptr_nonnull(s);
		ck_assert_str_eq(s, alg_map[j].str);
		ck_assert_int_eq(jwe_str_alg(alg_map[j].str), alg_map[j].alg);
	}

	/* Unknown / invalid inputs */
	ck_assert_ptr_null(jwe_alg_str(JWE_ALG_NONE));
	ck_assert_ptr_null(jwe_alg_str(JWE_ALG_INVAL));
	ck_assert_int_eq(jwe_str_alg(NULL), JWE_ALG_INVAL);
	ck_assert_int_eq(jwe_str_alg("bogus"), JWE_ALG_INVAL);
	ck_assert_int_eq(jwe_str_alg("RS256"), JWE_ALG_INVAL);
}
END_TEST

START_TEST(enc_roundtrip)
{
	size_t j;

	SET_OPS();

	for (j = 0; j < ARRAY_SIZE(enc_map); j++) {
		const char *s = jwe_enc_str(enc_map[j].enc);

		ck_assert_ptr_nonnull(s);
		ck_assert_str_eq(s, enc_map[j].str);
		ck_assert_int_eq(jwe_str_enc(enc_map[j].str), enc_map[j].enc);
	}

	ck_assert_ptr_null(jwe_enc_str(JWE_ENC_NONE));
	ck_assert_ptr_null(jwe_enc_str(JWE_ENC_INVAL));
	ck_assert_int_eq(jwe_str_enc(NULL), JWE_ENC_INVAL);
	ck_assert_int_eq(jwe_str_enc("bogus"), JWE_ENC_INVAL);
	ck_assert_int_eq(jwe_str_enc("A128GCMKW"), JWE_ENC_INVAL);
}
END_TEST

START_TEST(builder_new)
{
	jwe_builder_auto_t *builder = NULL;

	SET_OPS();

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwe_builder_error(builder), 0);
	ck_assert_str_eq(jwe_builder_error_msg(builder), "");

	/* NULL-safety */
	ck_assert_int_eq(jwe_builder_error(NULL), 1);
	ck_assert_ptr_null(jwe_builder_error_msg(NULL));
	jwe_builder_free(NULL);
	jwe_builder_error_clear(NULL);
}
END_TEST

START_TEST(checker_new)
{
	jwe_checker_auto_t *checker = NULL;

	SET_OPS();

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwe_checker_error(checker), 0);
	ck_assert_str_eq(jwe_checker_error_msg(checker), "");

	ck_assert_int_eq(jwe_checker_error(NULL), 1);
	ck_assert_ptr_null(jwe_checker_error_msg(NULL));
	jwe_checker_free(NULL);
	jwe_checker_error_clear(NULL);
}
END_TEST

START_TEST(builder_setkey)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	read_json("oct_key_256.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	/* Happy path */
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jwe_builder_error(builder), 0);

	/* Bad alg */
	ret = jwe_builder_setkey(builder, JWE_ALG_NONE, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_int_eq(jwe_builder_error(builder), 1);
	jwe_builder_error_clear(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_INVAL, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	jwe_builder_error_clear(builder);

	/* Bad enc */
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_NONE,
				 g_item);
	ck_assert_int_eq(ret, 1);
	jwe_builder_error_clear(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_INVAL,
				 g_item);
	ck_assert_int_eq(ret, 1);
	jwe_builder_error_clear(builder);

	/* No key */
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 NULL);
	ck_assert_int_eq(ret, 1);
	jwe_builder_error_clear(builder);

	/* NULL object */
	ret = jwe_builder_setkey(NULL, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);

	free_key();
}
END_TEST

START_TEST(checker_setkey)
{
	jwe_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	read_json("oct_key_256.json");

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwe_checker_setkey(checker, JWE_ALG_INVAL, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	jwe_checker_error_clear(checker);

	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_INVAL,
				 g_item);
	ck_assert_int_eq(ret, 1);
	jwe_checker_error_clear(checker);

	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 NULL);
	ck_assert_int_eq(ret, 1);
	jwe_checker_error_clear(checker);

	ret = jwe_checker_setkey(NULL, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE Foundation");

	/* The string maps and object lifecycle are crypto-backend
	 * independent, but run them under every compiled provider for
	 * consistency with the rest of the suite. */
	tcase_add_loop_test(tc_core, alg_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, enc_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, builder_new, 0, i);
	tcase_add_loop_test(tc_core, checker_new, 0, i);
	tcase_add_loop_test(tc_core, builder_setkey, 0, i);
	tcase_add_loop_test(tc_core, checker_setkey, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE Foundation");
}
