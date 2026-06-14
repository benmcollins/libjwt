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

static void roundtrip(const char *keyfile, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES, enc,
					    g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* ECDH-ES (Direct) has an empty Encrypted Key (like dir). */
	ck_assert_int_eq(count_dots(tok), 4);
	ck_assert_ptr_nonnull(strstr(tok, ".."));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES, enc,
					    g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_p256_gcm)
{
	SET_OPS();
	roundtrip("ec_key_prime256v1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_p256_cbc)
{
	SET_OPS();
	roundtrip("ec_key_prime256v1_enc.json", JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(rt_p384)
{
	SET_OPS();
	roundtrip("ec_key_secp384r1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_p521)
{
	SET_OPS();
	roundtrip("ec_key_secp521r1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(tamper_epk)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *hdr_end;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* The epk is in the protected header (first segment). Corrupting a
	 * header character changes both the agreed key and the AAD, so the
	 * decrypt must fail. */
	hdr_end = strchr(tok, '.');
	ck_assert_ptr_nonnull(hdr_end);
	/* Flip a char a few positions into the header (past kty/crv). */
	tok[20] = (tok[20] == 'A') ? 'B' : 'A';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
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

	read_json("ec_key_prime256v1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A different P-256 key derives a different CEK -> tag fails. */
	read_json("ec_key_prime256v1.json");
	checker = jwe_checker_new();
	/* The stock key is use:sig, so setkey itself rejects it. */
	ck_assert_int_ne(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	(void)pt;
	(void)pt_len;
	free_key();
}
END_TEST

START_TEST(curve_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	/* Encrypt to a P-256 recipient... */
	read_json("ec_key_prime256v1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...decrypt with a P-384 key: the epk curve will not match. */
	read_json("ec_key_secp384r1_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	free_key();
}
END_TEST

/* @rfc{7518,4.6} ECDH-ES+A*KW: the agreed key wraps a generated CEK, carried
 * in a non-empty Encrypted Key segment. */
static void kw_roundtrip(jwe_key_alg_t alg, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	/* Non-empty Encrypted Key (unlike Direct mode). */
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

START_TEST(kw_128)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A128KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(kw_192)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A192KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(kw_256)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A256KW, JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(kw_tamper_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *ek;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the Encrypted Key (2nd segment). @rfc{7516,11.5}: the unwrap
	 * fails, a random CEK is substituted, and the AEAD tag fails. */
	ek = strchr(tok, '.') + 1;
	ck_assert_int_ne(*ek, '.');
	*ek = (*ek == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(kw_bad_base64_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL, *bad = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *first_dot, *second_dot;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Replace the Encrypted Key segment with non-base64url junk so the
	 * decode (not the unwrap) is what fails -> @rfc{7516,11.5} random CEK. */
	first_dot = strchr(tok, '.');
	second_dot = strchr(first_dot + 1, '.');
	ck_assert_int_gt(asprintf(&bad, "%.*s.@@@@%s",
				  (int)(first_dot - tok), tok, second_dot), 0);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, bad, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(kw_empty_ek_rejected)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* ECDH-ES+A128KW with an empty Encrypted Key is invalid. Header is
	 * base64url({"alg":"ECDH-ES+A128KW","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZHQ00ifQ..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(decrypt_nonempty_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL, *bad = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *first_dot;
	int ret;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Splice a non-empty Encrypted Key into the (empty) second segment:
	 * replace "hdr.." with "hdr.X.". */
	first_dot = strstr(tok, "..");
	ck_assert_ptr_nonnull(first_dot);
	ret = asprintf(&bad, "%.*s.QUJD.%s",
		       (int)(first_dot - tok), tok, first_dot + 2);
	ck_assert_int_gt(ret, 0);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, bad, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(unsupported_curve)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;

	SET_OPS();

	/* secp256k1 is a valid EC key but not a JWE ECDH-ES curve. setkey
	 * accepts it (EC kty), but generation must fail. */
	read_json("ec_key_secp256k1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	free_key();
}
END_TEST

START_TEST(missing_epk)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);

	/* ECDH-ES token with no "epk" in the header must be rejected. Header
	 * is base64url({"alg":"ECDH-ES","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* Both backends route ECDH-ES to the OpenSSL EVP_PKEY, so a token from one
 * provider must decrypt under all. */
START_TEST(interop)
{
	char_auto *tok = NULL;
	size_t b;

	if (ARRAY_SIZE(jwt_test_ops) < 2)
		return;

	ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[0].name), 0);
	read_json("ec_key_prime256v1_enc.json");
	{
		jwe_builder_auto_t *builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
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
		read_json("ec_key_prime256v1_enc.json");
		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
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

	tc_core = tcase_create("JWE ECDH-ES");

	tcase_add_loop_test(tc_core, rt_p256_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_p256_cbc, 0, i);
	tcase_add_loop_test(tc_core, rt_p384, 0, i);
	tcase_add_loop_test(tc_core, rt_p521, 0, i);
	tcase_add_loop_test(tc_core, tamper_epk, 0, i);
	tcase_add_loop_test(tc_core, wrong_key, 0, i);
	tcase_add_loop_test(tc_core, curve_mismatch, 0, i);
	tcase_add_loop_test(tc_core, kw_128, 0, i);
	tcase_add_loop_test(tc_core, kw_192, 0, i);
	tcase_add_loop_test(tc_core, kw_256, 0, i);
	tcase_add_loop_test(tc_core, kw_tamper_ek, 0, i);
	tcase_add_loop_test(tc_core, kw_bad_base64_ek, 0, i);
	tcase_add_loop_test(tc_core, kw_empty_ek_rejected, 0, i);
	tcase_add_loop_test(tc_core, decrypt_nonempty_ek, 0, i);
	tcase_add_loop_test(tc_core, unsupported_curve, 0, i);
	tcase_add_loop_test(tc_core, missing_epk, 0, i);
	tcase_add_test(tc_core, interop);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE ECDH-ES");
}
