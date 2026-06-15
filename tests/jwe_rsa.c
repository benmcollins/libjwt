/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

/* GnuTLS/nettle has no SHA-1 RSA-OAEP, and the GnuTLS backend does not fall
 * back to OpenSSL, so it never supports plain RSA-OAEP (JWE_ALG_RSA_OAEP).
 * OpenSSL and MbedTLS do it natively. */
static int rsa_oaep_sha1_supported(jwt_crypto_provider_t type)
{
	return type != JWT_CRYPTO_OPS_GNUTLS;
}

static void roundtrip(jwe_key_alg_t alg, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	/* The private JWK carries the public half too, so one key both
	 * encrypts (build) and decrypts (check). */
	read_json("rsa_key_2048_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_oaep_gcm)
{
	SET_OPS();
	if (!rsa_oaep_sha1_supported(jwt_test_ops[_i].type))
		return;
	roundtrip(JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_oaep256_gcm)
{
	SET_OPS();
	roundtrip(JWE_ALG_RSA_OAEP_256, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_oaep256_cbc)
{
	SET_OPS();
	roundtrip(JWE_ALG_RSA_OAEP_256, JWE_ENC_A128CBC_HS256);
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
	read_json("rsa_key_2048_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* @rfc{7516,11.5} Corrupt the Encrypted Key. RSA-OAEP decryption will
	 * fail, but the checker must substitute a random CEK and fail only at
	 * the content tag, indistinguishably from a wrong key. */
	ek = strchr(tok, '.') + 1;
	ck_assert_int_ne(*ek, '.');
	*ek = (*ek == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_RSA_OAEP_256,
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

	/* Encrypt to the 2048-bit key... */
	read_json("rsa_key_2048_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...decrypt with a different RSA private key. The §11.5 path makes
	 * this fail at the tag, not at the RSA decryption. */
	read_json("rsa_key_4096_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(garbage_ek)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("rsa_key_2048_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, g_item), 0);

	/* @rfc{7516,11.5} A short/garbage Encrypted Key (QUJD = 3 bytes) must
	 * not produce a distinct error; the random-CEK path makes it fail at
	 * the tag like any other bad key. Header is
	 * base64url({"alg":"RSA-OAEP-256","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.QUJD.aa.bb.cc",
		&pt_len);
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

	tc_core = tcase_create("JWE RSA-OAEP");

	tcase_add_loop_test(tc_core, rt_oaep_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_oaep256_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_oaep256_cbc, 0, i);
	tcase_add_loop_test(tc_core, tamper_ek, 0, i);
	tcase_add_loop_test(tc_core, wrong_key, 0, i);
	tcase_add_loop_test(tc_core, garbage_ek, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE RSA-OAEP");
}
