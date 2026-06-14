/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "Live long and prosper.";
static const unsigned char AAD[] = "additional authenticated data";

/* @rfc{7516,5.1} step 14 A JSON-serialized JWE with an "aad" member round-trips,
 * and the checker hands the AAD octets back via get_aad. */
START_TEST(aad_roundtrip)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	const unsigned char *got;
	size_t pt_len = 0, got_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_eq(jwe_builder_set_aad(builder, AAD, strlen((char *)AAD)),
			 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "\"aad\":"));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);

	got = jwe_checker_get_aad(checker, &got_len);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(got_len, strlen((char *)AAD));
	ck_assert_mem_eq(got, AAD, got_len);

	free(pt);
	free_key();
}
END_TEST

/* set_aad(NULL) clears a previously set AAD; the resulting token has no aad
 * member and recovers no AAD. */
START_TEST(aad_clear)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_eq(jwe_builder_set_aad(builder, AAD, strlen((char *)AAD)),
			 0);
	/* Clear it again. */
	ck_assert_int_eq(jwe_builder_set_aad(builder, NULL, 0), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_null(strstr(tok, "\"aad\":"));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_ptr_null(jwe_checker_get_aad(checker, NULL));

	free(pt);
	free_key();
}
END_TEST

/* @rfc{7516,5.1} step 14 The AAD is bound into the AEAD tag: tampering with the
 * "aad" member must make decryption fail. */
START_TEST(aad_tamper)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *p;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_eq(jwe_builder_set_aad(builder, AAD, strlen((char *)AAD)),
			 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Flip a character inside the base64url aad value. */
	p = strstr(tok, "\"aad\":\"");
	ck_assert_ptr_nonnull(p);
	p += strlen("\"aad\":\"");
	*p = (*p == 'A') ? 'B' : 'A';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* Without an aad member, the JSON path's AAD equals the Compact path's AAD: a
 * token built as JSON_FLAT (no aad) and one built as COMPACT share the same
 * protected header and both decrypt. This pins that jwe_build_aad's no-aad
 * branch is byte-identical across the two paths. */
START_TEST(no_aad_matches_compact)
{
	jwe_builder_auto_t *bc = NULL, *bj = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *ct = NULL, *jt = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* dir keeps the protected header identical across both (just "enc" plus,
	 * for compact, "alg"); use A256KW so "alg" placement differs but the
	 * decrypt still succeeds either way. */
	bc = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bc, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ct = jwe_builder_generate(bc, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_nonnull(ct);

	bj = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bj, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(bj, JWE_FORMAT_JSON_FLAT), 0);
	jt = jwe_builder_generate(bj, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_nonnull(jt);

	/* Both decrypt with the same checker via auto-detect. */
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	pt = jwe_checker_decrypt_all(checker, ct, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);
	free(pt);

	pt = jwe_checker_decrypt_all(checker, jt, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);
	free(pt);

	free_key();
}
END_TEST

/* A CBC-HMAC content alg also binds the JSON AAD (the AAD length field AL and
 * the HMAC cover protected || '.' || aad). */
START_TEST(aad_cbc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	const unsigned char *got;
	size_t pt_len = 0, got_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_GENERAL), 0);
	ck_assert_int_eq(jwe_builder_set_aad(builder, AAD, strlen((char *)AAD)),
			 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);

	got = jwe_checker_get_aad(checker, &got_len);
	ck_assert_ptr_nonnull(got);
	ck_assert_mem_eq(got, AAD, got_len);

	free(pt);
	free_key();
}
END_TEST

/* get_aad must reflect only the most recent token: decrypting a JSON token with
 * AAD and then a token without AAD (compact, or JSON-without-aad) must leave no
 * stale AAD behind. Reusing one checker exercises the reset in decrypt_all. */
START_TEST(aad_not_stale)
{
	jwe_builder_auto_t *bj = NULL, *bc = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *jt = NULL, *ct = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* A JSON token carrying AAD. */
	bj = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bj, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(bj, JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_eq(jwe_builder_set_aad(bj, AAD, strlen((char *)AAD)), 0);
	jt = jwe_builder_generate(bj, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_nonnull(jt);

	/* A compact token (no AAD). */
	bc = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bc, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ct = jwe_builder_generate(bc, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_nonnull(ct);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* First the JSON token: AAD is recovered. */
	pt = jwe_checker_decrypt_all(checker, jt, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_ptr_nonnull(jwe_checker_get_aad(checker, NULL));
	free(pt);

	/* Then the compact token: the prior AAD must NOT linger. */
	pt = jwe_checker_decrypt_all(checker, ct, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_ptr_null(jwe_checker_get_aad(checker, NULL));
	free(pt);

	/* A subsequent early-failing decrypt must also leave no stale AAD: decrypt
	 * the JSON token again, then feed garbage. */
	pt = jwe_checker_decrypt_all(checker, jt, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_ptr_nonnull(jwe_checker_get_aad(checker, NULL));
	free(pt);
	jwe_checker_error_clear(checker);
	pt = jwe_checker_decrypt_all(checker, "{bad", &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_ptr_null(jwe_checker_get_aad(checker, NULL));

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE AAD");

	tcase_add_loop_test(tc_core, aad_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, aad_clear, 0, i);
	tcase_add_loop_test(tc_core, aad_tamper, 0, i);
	tcase_add_loop_test(tc_core, no_aad_matches_compact, 0, i);
	tcase_add_loop_test(tc_core, aad_cbc, 0, i);
	tcase_add_loop_test(tc_core, aad_not_stale, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE AAD");
}
