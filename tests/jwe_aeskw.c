/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

static int count_dots(const char *s)
{
	int n = 0;
	for (; *s; s++)
		if (*s == '.')
			n++;
	return n;
}

static void roundtrip(const char *keyfile, jwe_key_alg_t alg, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Five parts, and a NON-empty Encrypted Key segment (unlike dir). */
	ck_assert_int_eq(count_dots(tok), 4);
	ck_assert_ptr_null(strstr(tok, ".."));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_128_gcm)
{
	SET_OPS();
	roundtrip("oct_dir_128.json", JWE_ALG_A128KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_192_gcm)
{
	SET_OPS();
	roundtrip("oct_dir_192.json", JWE_ALG_A192KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_256_gcm)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ALG_A256KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_256_cbc)
{
	SET_OPS();
	/* AES-KW wrapping a 64-byte CBC-HMAC CEK. */
	roundtrip("oct_dir_256.json", JWE_ALG_A256KW, JWE_ENC_A256CBC_HS512);
}
END_TEST

START_TEST(tamper_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *ek;

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the first char of the Encrypted Key (2nd segment). The
	 * RFC 3394 integrity check must reject the unwrap. */
	ek = strchr(tok, '.') + 1;
	ck_assert_int_ne(*ek, '.');
	*ek = (*ek == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(wrong_kek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	read_json("oct_dir_256.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A different 256-bit KEK must fail to unwrap. */
	read_json("oct_key_256_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);

	free_key();
}
END_TEST

START_TEST(empty_ek_rejected)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* An A256KW token with an empty Encrypted Key is invalid. Header is
	 * base64url({"alg":"A256KW","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(kek_len_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	char *tok;

	SET_OPS();

	/* A 128-bit key cannot be used as the KEK for A256KW (needs 256-bit).
	 * The kty gate passes (both oct), but the wrap rejects the length. */
	read_json("oct_dir_128.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);
	free_key();
}
END_TEST

START_TEST(unwrap_kek_len_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	/* Build a valid A256KW token... */
	read_json("oct_dir_256.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...then try to unwrap with a 128-bit KEK configured as A256KW. The
	 * header says A256KW, so setkey/alg match, but the KEK length is wrong
	 * for the unwrap. */
	read_json("oct_dir_128.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	free_key();
}
END_TEST

START_TEST(bad_ek_base64)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* A256KW header with a non-base64url Encrypted Key segment. */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.@@@@.aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	jwe_checker_error_clear(checker);

	/* A valid-base64 but too-short Encrypted Key (QUJD = "ABC", 3 bytes;
	 * a wrapped key must be at least 24 bytes). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.QUJD.aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* Cross-backend interop: AES-KW (incl. the hand-rolled GnuTLS RFC 3394) must
 * be byte-compatible with OpenSSL's EVP_aes_*_wrap. */
START_TEST(interop)
{
	char_auto *tok = NULL;
	size_t b;

	if (ARRAY_SIZE(jwt_test_ops) < 2)
		return;

	ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[0].name), 0);
	read_json("oct_dir_256.json");
	{
		jwe_builder_auto_t *builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					JWE_ENC_A256GCM, g_item), 0);
		tok = jwe_builder_generate(builder, (const unsigned char *)PT,
					   strlen(PT));
		ck_assert_ptr_nonnull(tok);
	}
	free_key();

	for (b = 0; b < ARRAY_SIZE(jwt_test_ops); b++) {
		jwe_checker_auto_t *checker = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;

		ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[b].name), 0);
		read_json("oct_dir_256.json");
		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					JWE_ENC_A256GCM, g_item), 0);
		pt = jwe_checker_decrypt(checker, tok, &pt_len);
		ck_assert_ptr_nonnull(pt);
		ck_assert_mem_eq(pt, PT, strlen(PT));
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

	tc_core = tcase_create("JWE AES-KW");

	tcase_add_loop_test(tc_core, rt_128_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_192_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_256_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_256_cbc, 0, i);
	tcase_add_loop_test(tc_core, tamper_ek, 0, i);
	tcase_add_loop_test(tc_core, wrong_kek, 0, i);
	tcase_add_loop_test(tc_core, empty_ek_rejected, 0, i);
	tcase_add_loop_test(tc_core, kek_len_mismatch, 0, i);
	tcase_add_loop_test(tc_core, unwrap_kek_len_mismatch, 0, i);
	tcase_add_loop_test(tc_core, bad_ek_base64, 0, i);
	tcase_add_test(tc_core, interop);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE AES-KW");
}
