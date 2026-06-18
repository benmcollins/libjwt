/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7518,4.7} AES-GCM Key Wrap (A128/192/256GCMKW), issue #309. Runs under
 * each crypto backend (SET_OPS) and both JSON backends. The per-recipient
 * "iv"/"tag" header params are produced/consumed by the library; a fresh IV per
 * wrap is mandatory. */

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

static int count_dots(const char *s)
{
	int n = 0;

	for (; *s; s++)
		if (*s == '.')
			n++;

	return n;
}

/* Compact round-trip; the wrapped CEK is non-empty and the protected header
 * carries the GCM-KW "iv"/"tag". */
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

	/* Five parts, non-empty Encrypted Key (the wrapped CEK). */
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

START_TEST(rt_128)
{
	SET_OPS();
	roundtrip("oct_dir_128.json", JWE_ALG_A128GCMKW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_192)
{
	SET_OPS();
	roundtrip("oct_dir_192.json", JWE_ALG_A192GCMKW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_256)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ALG_A256GCMKW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_256_cbc)
{
	/* GCM-KW wrapping a 64-byte CBC-HMAC CEK. */
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ALG_A256GCMKW, JWE_ENC_A256CBC_HS512);
}
END_TEST

/* Two wraps of the same key must use different IVs (fresh CSPRNG IV per wrap).
 * Reuses one builder for both generates, which must not leak (the builder is
 * reusable). */
START_TEST(fresh_iv)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *t1 = NULL, *t2 = NULL;

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	t1 = jwe_builder_generate(builder, (const unsigned char *)PT, strlen(PT));
	t2 = jwe_builder_generate(builder, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_nonnull(t1);
	ck_assert_ptr_nonnull(t2);
	/* Different IV (and CEK) => the protected header + Encrypted Key differ. */
	ck_assert_str_ne(t1, t2);

	free_key();
}
END_TEST

/* JSON serialization: the "iv"/"tag" ride in the per-recipient header. */
static void roundtrip_json(jwe_serialization_t fmt)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder, fmt), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "\"iv\""));
	ck_assert_ptr_nonnull(strstr(tok, "\"tag\""));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_json_flat)
{
	SET_OPS();
	roundtrip_json(JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(rt_json_general)
{
	SET_OPS();
	roundtrip_json(JWE_FORMAT_JSON_GENERAL);
}
END_TEST

/* A corrupted Encrypted Key (the wrapped CEK) must fail the GCM key-unwrap tag,
 * funnel to a random CEK, and reject the token. */
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
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	ek = strchr(tok, '.') + 1;
	ck_assert_int_ne(*ek, '.');
	*ek = (*ek == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* A KEK whose length does not match the alg is rejected (at wrap time). */
START_TEST(wrong_kek_len)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;

	SET_OPS();
	read_json("oct_dir_128.json");	/* 128-bit KEK */

	builder = jwe_builder_new();
	/* A256GCMKW needs a 256-bit KEK; the mismatch fails the wrap. */
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256GCMKW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwe_gcmkw");

	tcase_add_loop_test(tc_core, rt_128, 0, i);
	tcase_add_loop_test(tc_core, rt_192, 0, i);
	tcase_add_loop_test(tc_core, rt_256, 0, i);
	tcase_add_loop_test(tc_core, rt_256_cbc, 0, i);
	tcase_add_loop_test(tc_core, fresh_iv, 0, i);
	tcase_add_loop_test(tc_core, rt_json_flat, 0, i);
	tcase_add_loop_test(tc_core, rt_json_general, 0, i);
	tcase_add_loop_test(tc_core, tamper_ek, 0, i);
	tcase_add_loop_test(tc_core, wrong_kek_len, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT AES-GCM Key Wrap (#309)");
}
