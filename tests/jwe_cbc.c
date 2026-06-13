/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

static void roundtrip(const char *keyfile, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR, enc, g_item),
			 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR, enc, g_item),
			 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_128)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(rt_192)
{
	SET_OPS();
	roundtrip("oct_dir_384.json", JWE_ENC_A192CBC_HS384);
}
END_TEST

START_TEST(rt_256)
{
	SET_OPS();
	roundtrip("oct_dir_512.json", JWE_ENC_A256CBC_HS512);
}
END_TEST

START_TEST(tamper_ct)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *seg;

	SET_OPS();
	read_json("oct_dir_512.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the first ciphertext char (4th segment). The HMAC tag must
	 * fail in the constant-time compare. */
	seg = tok;
	seg = strchr(seg, '.') + 1;	/* EK (empty) */
	seg = strchr(seg, '.') + 1;	/* iv */
	seg = strchr(seg, '.') + 1;	/* ct */
	ck_assert_int_ne(*seg, '\0');
	*seg = (*seg == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(tamper_tag)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t len, pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A128CBC_HS256, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the first character of the tag (final segment) by walking to
	 * the last dot. */
	len = strlen(tok);
	while (len > 0 && tok[len - 1] != '.')
		len--;
	ck_assert_int_gt(len, 0);
	tok[len] = (tok[len] == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A128CBC_HS256, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(wrong_key)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	read_json("oct_dir_512.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A different 64-byte key must not authenticate. */
	read_json("oct_key_512.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);

	free_key();
}
END_TEST

/* Cross-backend interop: a token produced by one crypto backend must decrypt
 * under every other compiled backend. This catches any divergence in the
 * AES-CBC padding or the HMAC tag construction between providers. */
START_TEST(interop)
{
	char_auto *tok = NULL;
	size_t b;

	if (ARRAY_SIZE(jwt_test_ops) < 2)
		return;

	/* Encrypt under provider 0. */
	ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[0].name), 0);
	read_json("oct_dir_512.json");
	{
		jwe_builder_auto_t *builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					JWE_ENC_A256CBC_HS512, g_item), 0);
		tok = jwe_builder_generate(builder, (const unsigned char *)PT,
					   strlen(PT));
		ck_assert_ptr_nonnull(tok);
	}
	free_key();

	/* Decrypt under every compiled provider. */
	for (b = 0; b < ARRAY_SIZE(jwt_test_ops); b++) {
		jwe_checker_auto_t *checker = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;

		ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[b].name), 0);
		read_json("oct_dir_512.json");
		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					JWE_ENC_A256CBC_HS512, g_item), 0);
		pt = jwe_checker_decrypt(checker, tok, &pt_len);
		ck_assert_ptr_nonnull(pt);
		ck_assert_int_eq(pt_len, strlen(PT));
		ck_assert_mem_eq(pt, PT, pt_len);
		free(pt);
		free_key();
	}
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE dir+CBC-HMAC");

	tcase_add_loop_test(tc_core, rt_128, 0, i);
	tcase_add_loop_test(tc_core, rt_192, 0, i);
	tcase_add_loop_test(tc_core, rt_256, 0, i);
	tcase_add_loop_test(tc_core, tamper_ct, 0, i);
	tcase_add_loop_test(tc_core, tamper_tag, 0, i);
	tcase_add_loop_test(tc_core, wrong_key, 0, i);
	tcase_add_test(tc_core, interop);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE dir+CBC-HMAC");
}
