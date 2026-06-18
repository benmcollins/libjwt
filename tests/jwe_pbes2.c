/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7518,4.8} PBES2 password-based key management
 * (PBES2-HS256+A128KW / HS384+A192KW / HS512+A256KW), issue #310. The oct key's
 * octets are the password. Runs under each crypto backend (SET_OPS) and both
 * JSON backends. A low p2c keeps the tests fast; the security checks (p2c cap,
 * short salt, wrong password) do not depend on it. */

static const char PT[] = "{\"sub\":\"1234567890\"}";
#define TEST_P2C 2048

/* Build a PBES2 token (JSON Flattened so p2s/p2c are plaintext-inspectable). */
static char *gen(const jwk_item_t *key, jwe_key_alg_t alg)
{
	jwe_builder_auto_t *b = jwe_builder_new();

	if (jwe_builder_setkey(b, alg, JWE_ENC_A256GCM, key) ||
	    jwe_builder_set_format(b, JWE_FORMAT_JSON_FLAT) ||
	    jwe_builder_setpbes2(b, TEST_P2C))
		return NULL;

	return jwe_builder_generate(b, (const unsigned char *)PT, strlen(PT));
}

static void roundtrip(jwe_key_alg_t alg)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json("oct_key_256_enc.json");

	tok = gen(g_item, alg);
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "\"p2s\":"));
	ck_assert_ptr_nonnull(strstr(tok, "\"p2c\":"));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, JWE_ENC_A256GCM,
					    g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_hs256)
{
	SET_OPS();
	roundtrip(JWE_ALG_PBES2_HS256_A128KW);
}
END_TEST

START_TEST(rt_hs384)
{
	SET_OPS();
	roundtrip(JWE_ALG_PBES2_HS384_A192KW);
}
END_TEST

START_TEST(rt_hs512)
{
	SET_OPS();
	roundtrip(JWE_ALG_PBES2_HS512_A256KW);
}
END_TEST

/* Compact Serialization carries p2s/p2c in the protected header. */
START_TEST(rt_compact)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_PBES2_HS256_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_setpbes2(builder, TEST_P2C), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_int_eq(tok[0] == '{', 0);	/* dotted compact, not JSON */

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_PBES2_HS256_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}
END_TEST

/* Replace the "p2c":N value in a JSON token with @repl and assert decrypt
 * fails (the cap / floor rejects before any PBKDF2 work). */
static void reject_with_p2c(const char *repl)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	char *mangled, *p;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char find[32];

	read_json("oct_key_256_enc.json");
	tok = gen(g_item, JWE_ALG_PBES2_HS256_A128KW);
	ck_assert_ptr_nonnull(tok);

	snprintf(find, sizeof(find), "\"p2c\":%d", TEST_P2C);
	p = strstr(tok, find);
	ck_assert_ptr_nonnull(p);

	mangled = malloc(strlen(tok) + strlen(repl) + 1);
	ck_assert_ptr_nonnull(mangled);
	memcpy(mangled, tok, p - tok);
	mangled[p - tok] = '\0';
	strcat(mangled, repl);
	strcat(mangled, p + strlen(find));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_PBES2_HS256_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, mangled, &pt_len);
	ck_assert_ptr_null(pt);

	free(pt);
	free(mangled);
	free_key();
}

/* An over-cap p2c is rejected (DoS guard) without running PBKDF2. */
START_TEST(p2c_over_cap_rejected)
{
	SET_OPS();
	reject_with_p2c("\"p2c\":2000000000");
}
END_TEST

/* A zero p2c is rejected. */
START_TEST(p2c_zero_rejected)
{
	SET_OPS();
	reject_with_p2c("\"p2c\":0");
}
END_TEST

/* A too-short p2s (salt) is rejected (RFC 7518 4.8.1.1 requires >= 8 octets).
 * "AAAA" base64url-decodes to 3 octets. */
START_TEST(short_salt_rejected)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	char *mangled, *p, *q;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");
	tok = gen(g_item, JWE_ALG_PBES2_HS256_A128KW);
	ck_assert_ptr_nonnull(tok);

	/* Replace the "p2s":"...." value with a 3-octet salt. */
	p = strstr(tok, "\"p2s\":\"");
	ck_assert_ptr_nonnull(p);
	q = strchr(p + 7, '"');		/* closing quote of the p2s value */
	ck_assert_ptr_nonnull(q);

	mangled = malloc(strlen(tok) + 16);
	ck_assert_ptr_nonnull(mangled);
	memcpy(mangled, tok, p - tok);
	mangled[p - tok] = '\0';
	strcat(mangled, "\"p2s\":\"AAAA\"");
	strcat(mangled, q + 1);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_PBES2_HS256_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, mangled, &pt_len);
	ck_assert_ptr_null(pt);

	free(pt);
	free(mangled);
	free_key();
}
END_TEST

/* A wrong password (different oct key) fails to decrypt. */
START_TEST(wrong_password)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("oct_key_256_enc.json");
	tok = gen(g_item, JWE_ALG_PBES2_HS256_A128KW);
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A different oct key (password) must not decrypt. */
	read_json("oct_dir_256.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_PBES2_HS256_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);

	free(pt);
	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwe_pbes2");

	tcase_add_loop_test(tc_core, rt_hs256, 0, i);
	tcase_add_loop_test(tc_core, rt_hs384, 0, i);
	tcase_add_loop_test(tc_core, rt_hs512, 0, i);
	tcase_add_loop_test(tc_core, rt_compact, 0, i);
	tcase_add_loop_test(tc_core, p2c_over_cap_rejected, 0, i);
	tcase_add_loop_test(tc_core, p2c_zero_rejected, 0, i);
	tcase_add_loop_test(tc_core, short_salt_rejected, 0, i);
	tcase_add_loop_test(tc_core, wrong_password, 0, i);

	tcase_set_timeout(tc_core, 60);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT PBES2 password-based key management (#310)");
}
