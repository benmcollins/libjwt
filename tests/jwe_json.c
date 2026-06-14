/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

/* Build a JSON-serialized JWE and decrypt it back, asserting the plaintext
 * round-trips and the structural expectations of the chosen form. */
static void roundtrip(const char *keyfile, jwe_key_alg_t alg, jwe_enc_t enc,
		      jwe_serialization_t fmt)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder, fmt), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* The JSON serialization is a JSON object, not a dotted string. */
	ck_assert_int_eq(tok[0], '{');
	ck_assert_ptr_nonnull(strstr(tok, "\"protected\":"));
	ck_assert_ptr_nonnull(strstr(tok, "\"ciphertext\":"));
	if (fmt == JWE_FORMAT_JSON_GENERAL)
		ck_assert_ptr_nonnull(strstr(tok, "\"recipients\":"));
	else
		ck_assert_ptr_null(strstr(tok, "\"recipients\":"));

	/* The decrypter auto-detects the JSON serialization. */
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(flat_dir_gcm)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ALG_DIR, JWE_ENC_A256GCM,
		  JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(flat_aeskw_gcm)
{
	SET_OPS();
	roundtrip("oct_key_256_enc.json", JWE_ALG_A256KW, JWE_ENC_A256GCM,
		  JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(flat_aeskw_cbc)
{
	SET_OPS();
	roundtrip("oct_key_256_enc.json", JWE_ALG_A256KW, JWE_ENC_A256CBC_HS512,
		  JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(flat_rsa_gcm)
{
	SET_OPS();
	roundtrip("rsa_key_2048_enc.json", JWE_ALG_RSA_OAEP_256, JWE_ENC_A256GCM,
		  JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(flat_ecdh_dir)
{
	SET_OPS();
	roundtrip("ec_key_prime256v1_enc.json", JWE_ALG_ECDH_ES,
		  JWE_ENC_A256GCM, JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(flat_ecdh_kw)
{
	SET_OPS();
	roundtrip("ec_key_secp521r1_enc.json", JWE_ALG_ECDH_ES_A256KW,
		  JWE_ENC_A256GCM, JWE_FORMAT_JSON_FLAT);
}
END_TEST

START_TEST(general_dir_gcm)
{
	SET_OPS();
	roundtrip("oct_dir_256.json", JWE_ALG_DIR, JWE_ENC_A256GCM,
		  JWE_FORMAT_JSON_GENERAL);
}
END_TEST

START_TEST(general_aeskw_gcm)
{
	SET_OPS();
	roundtrip("oct_key_256_enc.json", JWE_ALG_A256KW, JWE_ENC_A256GCM,
		  JWE_FORMAT_JSON_GENERAL);
}
END_TEST

START_TEST(general_rsa_cbc)
{
	SET_OPS();
	roundtrip("rsa_key_2048_enc.json", JWE_ALG_RSA_OAEP_256,
		  JWE_ENC_A192CBC_HS384, JWE_FORMAT_JSON_GENERAL);
}
END_TEST

START_TEST(general_ecdh_kw)
{
	SET_OPS();
	roundtrip("okp_x25519_enc.json", JWE_ALG_ECDH_ES_A128KW,
		  JWE_ENC_A256GCM, JWE_FORMAT_JSON_GENERAL);
}
END_TEST

/* @rfc{7516,7.2.1} For a JSON serialization, "alg" lives in the per-recipient
 * header, not the protected header; the protected header still carries "enc". */
START_TEST(alg_in_recipient_header)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_FLAT), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* protected decodes to {"enc":"A256GCM"} (no "alg"); the recipient header
	 * carries "alg":"A256KW". */
	ck_assert_ptr_nonnull(strstr(tok, "\"header\":{\"alg\":\"A256KW\"}"));
	ck_assert_ptr_nonnull(strstr(tok, "\"encrypted_key\":"));

	free_key();
}
END_TEST

/* Application-set protected and shared-unprotected header parameters survive a
 * round-trip and land in the right place. */
START_TEST(app_headers)
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
	ck_assert_int_eq(jwe_builder_add_protected_json(builder, "cty",
							"\"example\""), 0);
	ck_assert_int_eq(jwe_builder_add_unprotected_json(builder, "kid",
							  "\"2011-04-29\""), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	ck_assert_ptr_nonnull(strstr(tok, "\"unprotected\":{\"kid\":\"2011-04-29\"}"));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}
END_TEST

/* Reserved header names cannot be set by the application. */
START_TEST(reserved_header_rejected)
{
	jwe_builder_auto_t *builder = NULL;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	ck_assert_int_ne(jwe_builder_add_protected_json(builder, "enc",
							"\"A128GCM\""), 0);
	jwe_builder_error_clear(builder);
	ck_assert_int_ne(jwe_builder_add_protected_json(builder, "alg",
							"\"dir\""), 0);
	jwe_builder_error_clear(builder);
	ck_assert_int_ne(jwe_builder_add_unprotected_json(builder, "epk",
							  "{}"), 0);
	jwe_builder_error_clear(builder);

	/* A malformed JSON value is rejected. */
	ck_assert_int_ne(jwe_builder_add_protected_json(builder, "x",
							"{not json"), 0);
	jwe_builder_error_clear(builder);

	/* Setting the same protected parameter twice is rejected. */
	ck_assert_int_eq(jwe_builder_add_protected_json(builder, "cty",
							"\"a\""), 0);
	ck_assert_int_ne(jwe_builder_add_protected_json(builder, "cty",
							"\"b\""), 0);

	free_key();
}
END_TEST

/* The Compact Serialization cannot carry a shared unprotected header or aad. */
START_TEST(compact_rejects_json_only)
{
	jwe_builder_auto_t *builder = NULL;
	char *tok;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	/* Format defaults to compact. */
	ck_assert_int_eq(jwe_builder_add_unprotected_json(builder, "kid",
							  "\"x\""), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	free_key();
}
END_TEST

START_TEST(bad_format_rejected)
{
	jwe_builder_auto_t *builder = NULL;

	SET_OPS();

	builder = jwe_builder_new();
	ck_assert_int_ne(jwe_builder_set_format(builder,
						(jwe_serialization_t)99), 0);
	ck_assert_int_eq(jwe_builder_error(builder), 1);
}
END_TEST

/* A JSON object missing a required member, or with a wrong-typed member, is
 * rejected cleanly (and does NOT abort under json-c). */
START_TEST(json_structural_negatives)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;
	size_t i;
	static const char *bad[] = {
		/* Malformed top-level JSON (still routed to the JSON path by the
		 * leading '{'). */
		"{not valid json",
		/* Not a JWE object at all. */
		"{}",
		/* protected b64 decodes to invalid JSON. */
		"{\"protected\":\"e2JhZA\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* protected present but not a string. */
		"{\"protected\":123,\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* Missing ciphertext. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"iv\":\"a\",\"tag\":\"c\"}",
		/* recipients not an array. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":5,"
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* Empty recipients array. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":[],"
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* Both General and Flattened members present. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":"
			"[{\"encrypted_key\":\"x\"}],\"encrypted_key\":\"y\","
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* unprotected not an object. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"unprotected\":7,"
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* recipient header not an object. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"header\":9,"
			"\"encrypted_key\":\"x\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* No alg anywhere. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"encrypted_key\":\"x\","
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* protected not valid base64url / JSON. */
		"{\"protected\":\"@@@\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* protected decodes but is not a JSON object. */
		"{\"protected\":\"WzFd\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* protected has no "enc". */
		"{\"protected\":\"eyJ4IjoxfQ\",\"header\":{\"alg\":\"A256KW\"},"
			"\"encrypted_key\":\"x\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* Top-level (flattened) encrypted_key present but not a string. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\","
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":5,"
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* General: a recipient encrypted_key that is not a string. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":"
			"[{\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":5}],"
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* iv is not a string. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\","
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
			"\"iv\":5,\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* aad present but not a string. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\","
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
			"\"aad\":5,\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
		/* aad present but not valid base64url. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\","
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
			"\"aad\":\"@@@\",\"iv\":\"a\",\"ciphertext\":\"b\","
			"\"tag\":\"c\"}",
		/* zip is not supported. */
		"{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIn0\","
			"\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
			"\"iv\":\"a\",\"ciphertext\":\"b\",\"tag\":\"c\"}",
	};

	SET_OPS();
	read_json("oct_key_256_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		pt = jwe_checker_decrypt_all(checker, bad[i], &pt_len);
		ck_assert_ptr_null(pt);
		ck_assert_int_eq(jwe_checker_error(checker), 1);
		jwe_checker_error_clear(checker);
	}

	free_key();
}
END_TEST

/* An alg/enc that does not match the checker configuration is rejected. */
START_TEST(json_alg_mismatch)
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
						JWE_FORMAT_JSON_GENERAL), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Checker expects a different enc. */
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A128GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* decrypt_all still handles the Compact Serialization (auto-detect). */
START_TEST(decrypt_all_compact)
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
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	ck_assert_int_ne(tok[0], '{');

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, pt_len);

	/* A compact token carries no AAD member. */
	ck_assert_ptr_null(jwe_checker_get_aad(checker, NULL));

	free(pt);
	free_key();
}
END_TEST

/* NULL-safety and empty-token handling on the new entry points. */
START_TEST(api_nullsafe)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	size_t len = 99;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* Builder setters reject a NULL builder. */
	ck_assert_int_ne(jwe_builder_set_format(NULL, JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_ne(jwe_builder_set_aad(NULL, NULL, 0), 0);
	ck_assert_int_ne(jwe_builder_add_protected_json(NULL, "a", "1"), 0);
	ck_assert_int_ne(jwe_builder_add_unprotected_json(NULL, "a", "1"), 0);

	/* add_*_json reject a NULL key or value. */
	builder = jwe_builder_new();
	ck_assert_int_ne(jwe_builder_add_protected_json(builder, "a", NULL), 0);
	jwe_builder_error_clear(builder);
	ck_assert_int_ne(jwe_builder_add_unprotected_json(builder, NULL, "1"), 0);
	jwe_builder_error_clear(builder);

	ck_assert_ptr_null(jwe_checker_decrypt_all(NULL, "x", NULL));
	ck_assert_ptr_null(jwe_checker_get_aad(NULL, &len));

	checker = jwe_checker_new();
	/* No key set yet. */
	ck_assert_ptr_null(jwe_checker_decrypt_all(checker, "{}", NULL));
	jwe_checker_error_clear(checker);
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	/* Empty token. */
	ck_assert_ptr_null(jwe_checker_decrypt_all(checker, "", NULL));
	/* No AAD recovered yet. */
	ck_assert_ptr_null(jwe_checker_get_aad(checker, &len));
	ck_assert_int_eq(len, 0);

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE JSON Serialization");

	tcase_add_loop_test(tc_core, flat_dir_gcm, 0, i);
	tcase_add_loop_test(tc_core, flat_aeskw_gcm, 0, i);
	tcase_add_loop_test(tc_core, flat_aeskw_cbc, 0, i);
	tcase_add_loop_test(tc_core, flat_rsa_gcm, 0, i);
	tcase_add_loop_test(tc_core, flat_ecdh_dir, 0, i);
	tcase_add_loop_test(tc_core, flat_ecdh_kw, 0, i);
	tcase_add_loop_test(tc_core, general_dir_gcm, 0, i);
	tcase_add_loop_test(tc_core, general_aeskw_gcm, 0, i);
	tcase_add_loop_test(tc_core, general_rsa_cbc, 0, i);
	tcase_add_loop_test(tc_core, general_ecdh_kw, 0, i);
	tcase_add_loop_test(tc_core, alg_in_recipient_header, 0, i);
	tcase_add_loop_test(tc_core, app_headers, 0, i);
	tcase_add_loop_test(tc_core, reserved_header_rejected, 0, i);
	tcase_add_loop_test(tc_core, compact_rejects_json_only, 0, i);
	tcase_add_loop_test(tc_core, bad_format_rejected, 0, i);
	tcase_add_loop_test(tc_core, json_structural_negatives, 0, i);
	tcase_add_loop_test(tc_core, json_alg_mismatch, 0, i);
	tcase_add_loop_test(tc_core, decrypt_all_compact, 0, i);
	tcase_add_loop_test(tc_core, api_nullsafe, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE JSON Serialization");
}
