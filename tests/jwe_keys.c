/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7516,11.4} Key-usage gating is exercised through the public
 * jwe_builder_setkey / jwe_checker_setkey, which call the internal
 * jwe_key_usage_check. The builder is the producer (wrap/encrypt), the
 * checker the consumer (unwrap/decrypt). */

START_TEST(oct_no_restrictions)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* oct_key_256.json has no "use"/"key_ops" -> usable for A*KW/dir. */
	read_json("oct_key_256.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwe_builder_setkey(builder, JWE_ALG_DIR, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(oct_use_enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	/* use:enc, key_ops:[wrapKey,unwrapKey] */
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(oct_use_sig_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* use:sig must never be usable for JWE. */
	read_json("oct_key_256_sig.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_int_eq(jwe_builder_error(builder), 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key marked for signing cannot be used for JWE");

	free_key();
}
END_TEST

START_TEST(oct_key_ops_direction)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	/* key_ops:[wrapKey] only: builder (wrap) OK, checker (unwrap) rejected. */
	read_json("oct_key_256_wrap_only.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	checker = jwe_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwe_checker_setkey(checker, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_checker_error_msg(checker),
			 "Key does not permit the required JWE operation");

	free_key();
}
END_TEST

START_TEST(wrong_kty_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* An RSA key cannot be used for AES Key Wrap (needs oct). */
	read_json("rsa_key_2048.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_A256KW, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key type does not match JWE algorithm");

	free_key();
}
END_TEST

START_TEST(rsa_oaep_kty)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* use:enc RSA key is valid for RSA-OAEP. */
	read_json("rsa_key_2048_enc.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP_256, JWE_ENC_A128GCM,
				 g_item);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(rsa_sig_rejected)
{
	jwe_builder_auto_t *builder = NULL;
	int ret;

	SET_OPS();

	/* The stock RSA test key is use:sig and must be rejected for JWE. */
	read_json("rsa_key_2048.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key marked for signing cannot be used for JWE");

	free_key();

	/* An oct key cannot be used for RSA-OAEP regardless of usage. */
	read_json("oct_key_256.json");
	jwe_builder_error_clear(builder);
	ret = jwe_builder_setkey(builder, JWE_ALG_RSA_OAEP, JWE_ENC_A256GCM,
				 g_item);
	ck_assert_int_eq(ret, 1);
	ck_assert_str_eq(jwe_builder_error_msg(builder),
			 "Key type does not match JWE algorithm");

	free_key();
}
END_TEST

/* A key in error (jwks_item_error()) is never used for JWE. Each JWK here is in
 * error under every backend: the first group has no key material at all, the
 * second was flagged after its key material loaded and, before the errored-key
 * check existed, encrypted and decrypted like its valid twin. */
#define ERR_MSG "Key is in error and cannot be used for JWE"

#define EC_P256 "\"kty\":\"EC\",\"crv\":\"P-256\","		\
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","	\
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","	\
	"\"d\":\"wDvSCv8kxkqIVTYPpgEm4Efs6lKzf-95W8Qej4F1yEM\""
#define OCT_256 "\"kty\":\"oct\","				\
	"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\""

static const struct {
	const char *jwk;
	jwe_key_alg_t alg;
	jwe_enc_t enc;
} errored[] = {
	/* Failed to load: no key material. */
	{ "{\"kty\":\"oct\"}", JWE_ALG_DIR, JWE_ENC_A256GCM },
	{ "{\"kty\":\"oct\"}", JWE_ALG_A256KW, JWE_ENC_A256GCM },
	{ "{\"kty\":\"oct\",\"k\":\"\"}", JWE_ALG_A256GCMKW, JWE_ENC_A256GCM },
	{ "{\"kty\":\"oct\",\"k\":7}", JWE_ALG_PBES2_HS256_A128KW,
	  JWE_ENC_A128CBC_HS256 },
	{ "{\"kty\":\"RSA\",\"e\":\"AQAB\"}", JWE_ALG_RSA_OAEP_256,
	  JWE_ENC_A256GCM },
	{ "{\"kty\":\"EC\",\"crv\":\"P-256\","
	  "\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"}",
	  JWE_ALG_ECDH_ES, JWE_ENC_A256GCM },
	{ "{\"kty\":\"OKP\",\"crv\":\"X25519\"}", JWE_ALG_ECDH_ES_A256KW,
	  JWE_ENC_A256GCM },
	/* Loaded, then flagged: these have working key material. */
	{ "{" OCT_256 ",\"alg\":5}", JWE_ALG_DIR, JWE_ENC_A256GCM },
	/* "use" and "key_ops" are not even read once "alg" is rejected, so
	 * without the errored-key check this one passed for an unrestricted
	 * key. */
	{ "{" OCT_256 ",\"alg\":5,\"use\":\"sig\",\"key_ops\":[\"sign\"]}",
	  JWE_ALG_A256KW, JWE_ENC_A256GCM },
	{ "{" OCT_256 ",\"x5c\":\"not-an-array\"}", JWE_ALG_A256KW,
	  JWE_ENC_A256GCM },
	{ "{" OCT_256 ",\"x5c\":[1]}", JWE_ALG_A256GCMKW, JWE_ENC_A256GCM },
	{ "{" OCT_256 ",\"x5c\":[\"abc\"]}", JWE_ALG_PBES2_HS512_A256KW,
	  JWE_ENC_A256CBC_HS512 },
	{ "{" EC_P256 ",\"alg\":5}", JWE_ALG_ECDH_ES, JWE_ENC_A256GCM },
	{ "{" EC_P256 ",\"x5c\":\"not-an-array\"}", JWE_ALG_ECDH_ES_A128KW,
	  JWE_ENC_A128CBC_HS256 },
};

START_TEST(errored_key_rejected)
{
	size_t j;

	SET_OPS();

	for (j = 0; j < ARRAY_SIZE(errored); j++) {
		jwe_builder_auto_t *builder = NULL;
		jwe_checker_auto_t *checker = NULL;
		jwk_set_auto_t *set = NULL;
		const jwk_item_t *item;
		int ret;

		set = jwks_create(errored[j].jwk);
		ck_assert_ptr_nonnull(set);
		item = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwks_item_error(item), 0);

		/* Producer. */
		builder = jwe_builder_new();
		ck_assert_ptr_nonnull(builder);
		ret = jwe_builder_setkey(builder, errored[j].alg,
					 errored[j].enc, item);
		ck_assert_int_eq(ret, 1);
		ck_assert_int_eq(jwe_builder_error(builder), 1);
		ck_assert_str_eq(jwe_builder_error_msg(builder), ERR_MSG);

		/* Nothing was configured, so nothing is generated. */
		ck_assert_ptr_null(jwe_builder_generate(builder,
			(const unsigned char *)"x", 1));

		/* An additional recipient. */
		jwe_builder_error_clear(builder);
		ck_assert_ptr_null(jwe_builder_add_recipient(builder,
			errored[j].alg, item));
		ck_assert_str_eq(jwe_builder_error_msg(builder), ERR_MSG);

		/* Consumer. */
		checker = jwe_checker_new();
		ck_assert_ptr_nonnull(checker);
		ret = jwe_checker_setkey(checker, errored[j].alg,
					 errored[j].enc, item);
		ck_assert_int_eq(ret, 1);
		ck_assert_int_eq(jwe_checker_error(checker), 1);
		ck_assert_str_eq(jwe_checker_error_msg(checker), ERR_MSG);
	}
}
END_TEST

/* The flagged twin of a working key neither encrypts to nor decrypts a token
 * of that key, and a refused setkey leaves the key already set in place. */
START_TEST(errored_key_twin)
{
	static const char good[] = "{" OCT_256 "}";
	static const char bad[] = "{" OCT_256 ",\"alg\":5}";
	static const char pt_in[] = "twin";
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	jwk_set_auto_t *gset = NULL, *bset = NULL;
	const jwk_item_t *gitem, *bitem;
	char_auto *tok = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	gset = jwks_create(good);
	bset = jwks_create(bad);
	ck_assert_ptr_nonnull(gset);
	ck_assert_ptr_nonnull(bset);
	gitem = jwks_item_get(gset, 0);
	bitem = jwks_item_get(bset, 0);
	ck_assert_int_eq(jwks_item_error(gitem), 0);
	ck_assert_int_eq(jwks_item_error(bitem), 1);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, gitem), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)pt_in,
				   strlen(pt_in));
	ck_assert_ptr_nonnull(tok);

	/* The checker refuses the flagged twin, and so decrypts nothing. */
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, bitem), 1);
	ck_assert_str_eq(jwe_checker_error_msg(checker), ERR_MSG);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);

	/* With the good key set, a refused setkey changes nothing. */
	jwe_checker_error_clear(checker);
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, gitem), 0);
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, bitem), 1);
	jwe_checker_error_clear(checker);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(pt_in));
	ck_assert_mem_eq(pt, pt_in, pt_len);
	free(pt);
}
END_TEST

/* A refused recipient is simply not added: the builder still encrypts to the
 * recipients it has. */
START_TEST(errored_recipient_skipped)
{
	static const char good[] = "{" OCT_256 "}";
	static const char bad[] = "{" EC_P256 ",\"x5c\":\"not-an-array\"}";
	static const char pt_in[] = "recipients";
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	jwk_set_auto_t *gset = NULL, *bset = NULL;
	const jwk_item_t *gitem, *bitem;
	char_auto *tok = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	SET_OPS();

	gset = jwks_create(good);
	bset = jwks_create(bad);
	ck_assert_ptr_nonnull(gset);
	ck_assert_ptr_nonnull(bset);
	gitem = jwks_item_get(gset, 0);
	bitem = jwks_item_get(bset, 0);
	ck_assert_int_eq(jwks_item_error(bitem), 1);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, gitem), 0);
	ck_assert_ptr_null(jwe_builder_add_recipient(builder,
			   JWE_ALG_ECDH_ES_A256KW, bitem));
	ck_assert_str_eq(jwe_builder_error_msg(builder), ERR_MSG);
	jwe_builder_error_clear(builder);

	ck_assert_int_eq(jwe_builder_set_format(builder,
			 JWE_FORMAT_JSON_GENERAL), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)pt_in,
				   strlen(pt_in));
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_null(strstr(tok, "ECDH-ES"));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, gitem), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(pt_in));
	ck_assert_mem_eq(pt, pt_in, pt_len);
	free(pt);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE Key Usage");

	tcase_add_loop_test(tc_core, oct_no_restrictions, 0, i);
	tcase_add_loop_test(tc_core, oct_use_enc, 0, i);
	tcase_add_loop_test(tc_core, oct_use_sig_rejected, 0, i);
	tcase_add_loop_test(tc_core, oct_key_ops_direction, 0, i);
	tcase_add_loop_test(tc_core, wrong_kty_rejected, 0, i);
	tcase_add_loop_test(tc_core, rsa_oaep_kty, 0, i);
	tcase_add_loop_test(tc_core, rsa_sig_rejected, 0, i);
	tcase_add_loop_test(tc_core, errored_key_rejected, 0, i);
	tcase_add_loop_test(tc_core, errored_key_twin, 0, i);
	tcase_add_loop_test(tc_core, errored_recipient_skipped, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE Key Usage");
}
