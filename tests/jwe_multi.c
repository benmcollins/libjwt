/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "one plaintext, many recipients";

/* Decrypt @tok with (@alg, @key) from @keyfile and assert it returns PT. */
static void decrypt_ok(const char *tok, const char *keyfile,
		       jwe_key_alg_t alg, jwe_enc_t enc)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);
	free(pt);
	free_key();
}

/* A token encrypted to three recipients (A256KW, RSA-OAEP-256, ECDH-ES+A128KW)
 * decrypts with any one recipient's key. The content is encrypted once (one iv,
 * one ciphertext, one tag) and each recipient gets its own encrypted_key. */
START_TEST(three_recipients)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_recipient_t *r;
	char_auto *tok = NULL;
	jwk_set_auto_t *ks_rsa = NULL, *ks_ec = NULL;
	const jwk_item_t *k_rsa, *k_ec;

	SET_OPS();

	/* Recipient 0 via setkey (oct A256KW). */
	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* Recipients 1 and 2 via add_recipient. */
	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	ck_assert_ptr_nonnull(ks_rsa);
	k_rsa = jwks_item_get(ks_rsa, 0);
	r = jwe_builder_add_recipient(builder, JWE_ALG_RSA_OAEP_256, k_rsa);
	ck_assert_ptr_nonnull(r);

	ks_ec = jwks_create_fromfile(KEYDIR "/ec_key_prime256v1_enc.json");
	ck_assert_ptr_nonnull(ks_ec);
	k_ec = jwks_item_get(ks_ec, 0);
	r = jwe_builder_add_recipient(builder, JWE_ALG_ECDH_ES_A128KW, k_ec);
	ck_assert_ptr_nonnull(r);

	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* General form: a recipients array, exactly one iv/ciphertext/tag. */
	ck_assert_int_eq(tok[0], '{');
	ck_assert_ptr_nonnull(strstr(tok, "\"recipients\":"));
	ck_assert_ptr_nonnull(strstr(tok, "\"ciphertext\":"));

	/* Each recipient's key decrypts the same token. */
	decrypt_ok(tok, "oct_key_256_enc.json", JWE_ALG_A256KW, JWE_ENC_A256GCM);
	decrypt_ok(tok, "rsa_key_2048_enc.json", JWE_ALG_RSA_OAEP_256,
		   JWE_ENC_A256GCM);
	decrypt_ok(tok, "ec_key_prime256v1_enc.json", JWE_ALG_ECDH_ES_A128KW,
		   JWE_ENC_A256GCM);

	free_key();
}
END_TEST

/* The recipient that matches our key may be the second one in the array; it
 * still decrypts (selection iterates all recipients). */
START_TEST(second_recipient_matches)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;

	SET_OPS();

	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);
	ck_assert_ptr_nonnull(jwe_builder_add_recipient(builder,
					JWE_ALG_RSA_OAEP_256, k_rsa));
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Our key is recipient #2 (RSA), not #1 (A256KW). */
	decrypt_ok(tok, "rsa_key_2048_enc.json", JWE_ALG_RSA_OAEP_256,
		   JWE_ENC_A256GCM);

	free_key();
}
END_TEST

/* Per-recipient partyinfo and an application header parameter survive to the
 * per-recipient header. */
START_TEST(recipient_header_and_partyinfo)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_recipient_t *r;
	char_auto *tok = NULL;

	SET_OPS();

	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_GENERAL), 0);

	/* setkey configures recipient 0 (no handle); add a second recipient
	 * whose handle we use for per-recipient partyinfo/header. */
	read_json("ec_key_secp521r1_enc.json");
	r = jwe_builder_add_recipient(builder, JWE_ALG_ECDH_ES_A256KW, g_item);
	ck_assert_ptr_nonnull(r);
	ck_assert_int_eq(jwe_recipient_set_partyinfo(r,
				(const unsigned char *)"Alice", 5,
				(const unsigned char *)"Bob", 3), 0);
	ck_assert_int_eq(jwe_recipient_add_header_json(r, "kid", "\"ec-1\""), 0);
	/* Reserved names and NULLs are rejected. */
	ck_assert_int_ne(jwe_recipient_add_header_json(r, "alg", "\"x\""), 0);
	ck_assert_int_ne(jwe_recipient_add_header_json(r, "kid", "\"dup\""), 0);
	ck_assert_int_ne(jwe_recipient_add_header_json(NULL, "a", "1"), 0);
	ck_assert_int_ne(jwe_recipient_set_partyinfo(NULL, NULL, 0, NULL, 0), 0);

	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "\"kid\":\"ec-1\""));
	ck_assert_ptr_nonnull(strstr(tok, "\"apu\":"));

	/* Recipient 1 (the EC one) decrypts. */
	decrypt_ok(tok, "ec_key_secp521r1_enc.json", JWE_ALG_ECDH_ES_A256KW,
		   JWE_ENC_A256GCM);

	free_key();
}
END_TEST

/* add_recipient and the recipient setters validate their inputs. */
START_TEST(add_recipient_errors)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_recipient_t *r;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* NULL builder. */
	ck_assert_ptr_null(jwe_builder_add_recipient(NULL, JWE_ALG_A256KW,
						     g_item));

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* Invalid alg. */
	ck_assert_ptr_null(jwe_builder_add_recipient(builder, JWE_ALG_NONE,
						     g_item));
	jwe_builder_error_clear(builder);
	ck_assert_ptr_null(jwe_builder_add_recipient(builder, JWE_ALG_INVAL,
						     g_item));
	jwe_builder_error_clear(builder);
	/* NULL key. */
	ck_assert_ptr_null(jwe_builder_add_recipient(builder, JWE_ALG_A256KW,
						     NULL));
	jwe_builder_error_clear(builder);

	/* A signing key is rejected by the usage gate. */
	free_key();
	read_json("rsa_key_2048.json");
	r = jwe_builder_add_recipient(builder, JWE_ALG_RSA_OAEP_256, g_item);
	if (r == NULL)
		ck_assert_int_eq(jwe_builder_error(builder), 1);
	jwe_builder_error_clear(builder);

	/* Recipient setter input validation. */
	free_key();
	read_json("oct_key_256_enc.json");
	r = jwe_builder_add_recipient(builder, JWE_ALG_A256KW, g_item);
	ck_assert_ptr_nonnull(r);
	ck_assert_int_ne(jwe_recipient_add_header_json(r, NULL, "1"), 0);
	ck_assert_int_ne(jwe_recipient_add_header_json(r, "x", NULL), 0);
	ck_assert_int_ne(jwe_recipient_add_header_json(r, "x", "{bad json"), 0);

	free_key();
}
END_TEST

/* dir cannot be combined with another recipient (both orderings). */
START_TEST(dir_rejects_multi)
{
	jwe_builder_auto_t *b1 = NULL, *b2 = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;

	SET_OPS();

	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);

	/* dir first, then add another recipient -> rejected. */
	read_json("oct_dir_256.json");
	b1 = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(b1, JWE_ALG_DIR,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_ptr_null(jwe_builder_add_recipient(b1, JWE_ALG_RSA_OAEP_256,
						     k_rsa));
	ck_assert_int_eq(jwe_builder_error(b1), 1);

	/* Another recipient first, then dir -> rejected. */
	b2 = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(b2, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, k_rsa), 0);
	read_json("oct_dir_256.json");
	ck_assert_ptr_null(jwe_builder_add_recipient(b2, JWE_ALG_DIR, g_item));
	ck_assert_int_eq(jwe_builder_error(b2), 1);

	free_key();
}
END_TEST

/* ECDH-ES Direct also cannot be combined with another recipient. */
START_TEST(ecdh_direct_rejects_multi)
{
	jwe_builder_auto_t *builder = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;

	SET_OPS();

	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);

	read_json("ec_key_prime256v1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_ptr_null(jwe_builder_add_recipient(builder,
					JWE_ALG_RSA_OAEP_256, k_rsa));
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	free_key();
}
END_TEST

/* Flattened and Compact reject a second recipient at generate time. */
START_TEST(flat_compact_reject_multi)
{
	jwe_builder_auto_t *bf = NULL, *bc = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;
	char *tok;

	SET_OPS();

	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);

	/* Flattened + 2 recipients -> generate fails. */
	read_json("oct_key_256_enc.json");
	bf = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bf, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_ptr_nonnull(jwe_builder_add_recipient(bf, JWE_ALG_RSA_OAEP_256,
							k_rsa));
	/* add_recipient forced GENERAL; force it back to FLAT to trip the gate. */
	ck_assert_int_eq(jwe_builder_set_format(bf, JWE_FORMAT_JSON_FLAT), 0);
	tok = jwe_builder_generate(bf, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(bf), 1);

	/* Compact + 2 recipients -> generate fails. */
	read_json("oct_key_256_enc.json");
	bc = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(bc, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_ptr_nonnull(jwe_builder_add_recipient(bc, JWE_ALG_RSA_OAEP_256,
							k_rsa));
	ck_assert_int_eq(jwe_builder_set_format(bc, JWE_FORMAT_COMPACT), 0);
	tok = jwe_builder_generate(bc, (const unsigned char *)PT, strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(bc), 1);

	free_key();
}
END_TEST

/* A checker whose key/alg matches no recipient fails with the generic auth
 * error (RFC 7516 11.5: no oracle revealing which recipient, if any, matched). */
START_TEST(no_matching_recipient)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);
	ck_assert_ptr_nonnull(jwe_builder_add_recipient(builder,
					JWE_ALG_RSA_OAEP_256, k_rsa));
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* Checker configured for ECDH-ES, which no recipient uses. */
	read_json("ec_key_prime256v1_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* The right key but wrong recipient's key still fails (wrong A256KW KEK while
 * the matching alg recipient exists). */
START_TEST(matching_alg_wrong_key)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	jwk_set_auto_t *ks_rsa = NULL;
	const jwk_item_t *k_rsa;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ks_rsa = jwks_create_fromfile(KEYDIR "/rsa_key_2048_enc.json");
	k_rsa = jwks_item_get(ks_rsa, 0);
	ck_assert_ptr_nonnull(jwe_builder_add_recipient(builder,
					JWE_ALG_RSA_OAEP_256, k_rsa));
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A256KW alg matches recipient #1, but a different 256-bit KEK. */
	read_json("oct_dir_256.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* No matching recipient AND an aad member present: the uniform-failure path
 * must build (and free) the AAD too. */
START_TEST(no_match_with_aad)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	read_json("oct_key_256_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_GENERAL), 0);
	ck_assert_int_eq(jwe_builder_set_aad(builder,
				(const unsigned char *)"aad", 3), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* Checker configured for an alg no recipient uses. */
	read_json("rsa_key_2048_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_RSA_OAEP_256,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
	/* No AAD surfaced on failure. */
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

	tc_core = tcase_create("JWE Multi-Recipient");

	tcase_add_loop_test(tc_core, three_recipients, 0, i);
	tcase_add_loop_test(tc_core, second_recipient_matches, 0, i);
	tcase_add_loop_test(tc_core, recipient_header_and_partyinfo, 0, i);
	tcase_add_loop_test(tc_core, add_recipient_errors, 0, i);
	tcase_add_loop_test(tc_core, dir_rejects_multi, 0, i);
	tcase_add_loop_test(tc_core, ecdh_direct_rejects_multi, 0, i);
	tcase_add_loop_test(tc_core, flat_compact_reject_multi, 0, i);
	tcase_add_loop_test(tc_core, no_matching_recipient, 0, i);
	tcase_add_loop_test(tc_core, no_match_with_aad, 0, i);
	tcase_add_loop_test(tc_core, matching_alg_wrong_key, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE Multi-Recipient");
}
