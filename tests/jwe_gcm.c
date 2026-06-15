/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

/* Count the dots in a compact token. */
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
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR, enc, g_item),
			 0);

	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 0);

	/* Five parts (4 dots), with an empty Encrypted Key segment for dir. */
	ck_assert_int_eq(count_dots(tok), 4);
	ck_assert_ptr_nonnull(strstr(tok, ".."));

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR, enc, g_item),
			 0);

	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 0);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(roundtrip_128)
{
	SET_OPS();
	roundtrip("oct_dir_128.json", JWE_ENC_A128GCM);
}
END_TEST

START_TEST(roundtrip_192)
{
	SET_OPS();
	roundtrip("oct_dir_192.json", JWE_ENC_A192GCM);
}
END_TEST

START_TEST(roundtrip_256)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(tamper_ct_fails)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *ct_seg;

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the first character of the ciphertext (4th of 5 segments:
	 * hdr . EK . iv . CT . tag). Changing the base64url char to a clearly
	 * distinct value guarantees a different decoded byte, so the GCM tag
	 * must fail to verify. */
	ct_seg = tok;
	ct_seg = strchr(ct_seg, '.') + 1;	/* start of EK (empty) */
	ct_seg = strchr(ct_seg, '.') + 1;	/* start of iv */
	ct_seg = strchr(ct_seg, '.') + 1;	/* start of ct */
	ck_assert_int_ne(*ct_seg, '\0');
	ck_assert_int_ne(*ct_seg, '.');
	*ct_seg = (*ct_seg == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* A GCM token whose IV is not 96 bits must be rejected (RFC 7518 5.3 fixes the
 * GCM IV at 12 bytes). With the central iv_len gate the token is rejected as
 * malformed before the cipher runs; without it the wrong IV would change J0 and
 * the GCM tag check would fail anyway, so the observable outcome is the same.
 * This is therefore a conformance regression guard rather than a bypass test:
 * it pins that a non-12-byte IV never decrypts. Replace the 12-byte IV segment
 * with a 16-byte one (still valid base64url) and require rejection. */
START_TEST(gcm_wrong_iv_len_fails)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	char *bad = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *iv_start, *iv_end;
	/* base64url of 16 bytes "abcdefghijklmnop" (no padding). */
	static const char iv16[] = "YWJjZGVmZ2hpamtsbW5vcA";

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Locate the IV segment (3rd of 5: hdr . EK . iv . ct . tag). */
	iv_start = strchr(tok, '.') + 1;	/* start of EK (empty) */
	iv_start = strchr(iv_start, '.') + 1;	/* start of iv */
	iv_end = strchr(iv_start, '.');		/* end of iv */
	ck_assert_ptr_nonnull(iv_end);

	/* Rebuild the token with the oversized IV in place of the original. */
	ck_assert_int_gt(asprintf(&bad, "%.*s%s%s",
				  (int)(iv_start - tok), tok, iv16, iv_end), 0);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, bad, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free(bad);
	free_key();
}
END_TEST

START_TEST(wrong_key_fails)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	/* Encrypt with one 256-bit key... */
	read_json("oct_dir_256.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...decrypt with a different 256-bit key. */
	read_json("oct_key_256_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(dir_wrong_len)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;

	SET_OPS();

	/* A 256-bit key cannot be used as a dir CEK for A128GCM (needs 128). */
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A128GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	free_key();
}
END_TEST

START_TEST(reject_non_jwe)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);

	/* A 3-part JWS-shaped token has the wrong number of parts. */
	pt = jwe_checker_decrypt(checker,
				 "eyJhbGciOiJub25lIn0.eyJhIjoxfQ.", &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	jwe_checker_error_clear(checker);

	/* Garbage / empty. */
	pt = jwe_checker_decrypt(checker, "", &pt_len);
	ck_assert_ptr_null(pt);

	free_key();
}
END_TEST

START_TEST(alg_enc_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Checker configured for a different enc than the token carries. */
	read_json("oct_dir_128.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A128GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(generate_errors)
{
	jwe_builder_auto_t *builder = NULL;
	char *tok;

	SET_OPS();

	/* NULL object. */
	ck_assert_ptr_null(jwe_builder_generate(NULL,
				(const unsigned char *)PT, strlen(PT)));

	/* No setkey -> no key/alg set. */
	builder = jwe_builder_new();
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	/* NULL plaintext with non-zero length. */
	read_json("oct_dir_256.json");
	jwe_builder_error_clear(builder);
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, NULL, 5);
	ck_assert_ptr_null(tok);
	free_key();
}
END_TEST

START_TEST(decrypt_errors)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	/* NULL object. */
	ck_assert_ptr_null(jwe_checker_decrypt(NULL, "a.b.c.d.e", &pt_len));

	/* No setkey. */
	checker = jwe_checker_new();
	pt = jwe_checker_decrypt(checker, "a.b.c.d.e", &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	read_json("oct_dir_256.json");
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);

	/* Header that is not valid base64url / not JSON. */
	jwe_checker_error_clear(checker);
	pt = jwe_checker_decrypt(checker, "!!!!..aa.bb.cc", &pt_len);
	ck_assert_ptr_null(pt);

	/* Valid base64url header that is not a JSON object. */
	jwe_checker_error_clear(checker);
	/* base64url("123") = "MTIz" -> parses as a JSON number, no alg/enc. */
	pt = jwe_checker_decrypt(checker, "MTIz..aa.bb.cc", &pt_len);
	ck_assert_ptr_null(pt);

	free_key();
}
END_TEST

START_TEST(decrypt_header_cases)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);

	/* A header with no "enc" (a JWS-style header) -> not a JWE.
	 * base64url('{"alg":"dir"}') computed below by encoding via builder is
	 * overkill; use a known-good encoding. */
	/* {"alg":"dir"} */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJkaXIifQ..aa.bb.cc", &pt_len);
	ck_assert_ptr_null(pt);
	jwe_checker_error_clear(checker);

	/* A header carrying "zip" must be rejected. Build a normal token,
	 * then splice in a zip header. Easiest: craft the header directly.
	 * {"alg":"dir","enc":"A256GCM","zip":"DEF"} */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIn0..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	jwe_checker_error_clear(checker);

	/* @rfc{7516} dir must carry an empty Encrypted Key. A token whose
	 * header is dir+A256GCM but with a non-empty EK segment must be
	 * rejected at that check. Header is base64url({"alg":"dir","enc":
	 * "A256GCM"}) (sorted keys, as the builder emits). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.QUJD.aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	jwe_checker_error_clear(checker);

	free_key();
}
END_TEST

START_TEST(decrypt_cek_cases)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	/* dir + A128GCM token, but checker holds a 256-bit key: the dir CEK
	 * length will not match what A128GCM requires. Header is
	 * base64url({"alg":"dir","enc":"A128GCM"}). */
	read_json("oct_dir_256.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A128GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..aa.bb.cc", &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	free_key();
}
END_TEST

START_TEST(decrypt_bad_components)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_dir_256.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);

	/* Valid dir+A256GCM header but an empty IV segment -> decode yields a
	 * zero-length IV, which is rejected. Header is
	 * base64url({"alg":"dir","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0...bb.cc", &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE dir+GCM");

	tcase_add_loop_test(tc_core, roundtrip_128, 0, i);
	tcase_add_loop_test(tc_core, roundtrip_192, 0, i);
	tcase_add_loop_test(tc_core, roundtrip_256, 0, i);
	tcase_add_loop_test(tc_core, tamper_ct_fails, 0, i);
	tcase_add_loop_test(tc_core, gcm_wrong_iv_len_fails, 0, i);
	tcase_add_loop_test(tc_core, wrong_key_fails, 0, i);
	tcase_add_loop_test(tc_core, dir_wrong_len, 0, i);
	tcase_add_loop_test(tc_core, reject_non_jwe, 0, i);
	tcase_add_loop_test(tc_core, alg_enc_mismatch, 0, i);
	tcase_add_loop_test(tc_core, generate_errors, 0, i);
	tcase_add_loop_test(tc_core, decrypt_errors, 0, i);
	tcase_add_loop_test(tc_core, decrypt_header_cases, 0, i);
	tcase_add_loop_test(tc_core, decrypt_cek_cases, 0, i);
	tcase_add_loop_test(tc_core, decrypt_bad_components, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE dir+GCM");
}
