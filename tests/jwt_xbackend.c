/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Backend affinity (issue #320): a jwk_item is bound to the crypto backend that
 * parsed it, and key operations route to that backend regardless of the active
 * jwt_ops. Each test sets the active backend with SET_OPS() (the "use" backend),
 * then parses a key under EVERY backend (the "parse" backend) and exercises it
 * under the active one. Before affinity, a cross-backend asymmetric key failed
 * ("Key is not compatible"); now every (parse, use) pair must succeed. */

static const char PT[] = "cross-backend proof-of-possession plaintext";

static jwk_set_t *load_under(size_t ops_idx, const char *file)
{
	char *path;
	jwk_set_t *set;
	int ret;

	/* Parse the JWK under jwt_test_ops[ops_idx]; this binds item->provider. */
	ret = jwt_set_crypto_ops(jwt_test_ops[ops_idx].name);
	ck_assert_int_eq(ret, 0);

	ret = asprintf(&path, KEYDIR "/%s", file);
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

static const struct {
	const char *file;
	jwt_alg_t alg;
} sig_keys[] = {
	{ "ec_key_prime256v1.json", JWT_ALG_ES256 },	/* backend-specific */
	{ "rsa_key_2048.json",      JWT_ALG_RS256 },	/* backend-specific */
	{ "oct_key_256.json",       JWT_ALG_HS256 },	/* cross-compatible (ANY) */
};

START_TEST(test_xbackend_sign_verify)
{
	size_t k, p;

	SET_OPS(); /* active ("use") backend = jwt_test_ops[_i] */

	for (k = 0; k < ARRAY_SIZE(sig_keys); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			jwt_builder_auto_t *builder = NULL;
			jwt_checker_auto_t *checker = NULL;
			char_auto *token = NULL;
			jwk_set_t *set;
			const jwk_item_t *key;

			/* Parse under backend p ... */
			set = load_under(p, sig_keys[k].file);
			key = jwks_item_get(set, 0);
			ck_assert_ptr_nonnull(key);

			/* ... then switch the active backend to the use one. */
			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);

			builder = jwt_builder_new();
			ck_assert_int_eq(jwt_builder_setkey(builder,
				sig_keys[k].alg, key), 0);
			token = jwt_builder_generate(builder);
			ck_assert_ptr_nonnull(token);

			checker = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkey(checker,
				sig_keys[k].alg, key), 0);
			ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

			jwks_free(set);
		}
	}
}
END_TEST

static void jwe_roundtrip_xbackend(size_t use_i, jwe_key_alg_t alg,
				   jwe_enc_t enc, const char *file)
{
	size_t p;

	for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
		jwe_builder_auto_t *builder = NULL;
		jwe_checker_auto_t *checker = NULL;
		char_auto *token = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;
		jwk_set_t *set;
		const jwk_item_t *key;

		set = load_under(p, file);
		key = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(key);

		ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[use_i].name), 0);

		builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, key), 0);
		token = jwe_builder_generate(builder, (const unsigned char *)PT,
					     strlen(PT));
		ck_assert_ptr_nonnull(token);

		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, key), 0);
		pt = jwe_checker_decrypt(checker, token, &pt_len);
		ck_assert_ptr_nonnull(pt);
		ck_assert_uint_eq(pt_len, strlen(PT));
		ck_assert_mem_eq(pt, PT, pt_len);
		free(pt);

		jwks_free(set);
	}
}

START_TEST(test_xbackend_jwe_rsa)
{
	SET_OPS();
	/* RSA-OAEP-256 wraps the CEK with the recipient RSA key (decrypt_cek_rsa
	 * / encrypt_cek_rsa route to the key's backend). */
	jwe_roundtrip_xbackend(_i, JWE_ALG_RSA_OAEP_256, JWE_ENC_A256GCM,
			       "rsa_key_2048_enc.json");
}
END_TEST

START_TEST(test_xbackend_jwe_ecdh)
{
	SET_OPS();
	/* ECDH-ES derives the agreed key from the recipient EC key (ecdh_derive
	 * routes to the key's backend). */
	jwe_roundtrip_xbackend(_i, JWE_ALG_ECDH_ES_A256KW, JWE_ENC_A256GCM,
			       "ec_key_prime256v1_enc.json");
}
END_TEST

/* Free a key while a DIFFERENT backend is active than the one that parsed it.
 * Only the origin backend can release the key's provider_data, so this must not
 * leak (issue #327, completing #320). The leak is proven absent by the
 * memcheck CI row; here we just exercise every (parse, free) backend pair. */
START_TEST(test_xbackend_free)
{
	static const char *files[] = {
		"ec_key_prime256v1.json",	/* EC: EVP_PKEY / PSA / gnutls key */
		"rsa_key_2048.json",		/* RSA */
		"oct_key_256.json",		/* oct: backend-agnostic (ANY) */
	};
	size_t k, p;

	SET_OPS(); /* the active ("free") backend = jwt_test_ops[_i] */

	for (k = 0; k < ARRAY_SIZE(files); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			/* Parse under backend p ... */
			jwk_set_t *set = load_under(p, files[k]);

			/* ... then free while the use backend (_i) is active. */
			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);
			jwks_free(set);
		}
	}
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_xbackend");

	tcase_add_loop_test(tc_core, test_xbackend_sign_verify, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_jwe_rsa, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_jwe_ecdh, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_free, 0, i);

	tcase_set_timeout(tc_core, 60);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT cross-backend key affinity (#320)");
}
