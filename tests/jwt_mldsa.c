/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for ML-DSA (FIPS 204 / RFC 9964) signing. These only do anything in a
 * build configured with -DWITH_ML_DSA=ON against a backend that implements it
 * (OpenSSL >= 3.5); otherwise LIBJWT_HAVE_ML_DSA is undefined and the suite is
 * an intentional no-op so the test binary still builds and passes. */

#ifdef LIBJWT_HAVE_ML_DSA

static const struct {
	const char *priv;	/* private JWK fixture (kty=AKP, pub+priv)  */
	const char *pub;	/* public JWK fixture (kty=AKP, pub only)   */
	jwt_alg_t alg;
	const char *hdr;	/* expected base64url JWS protected header  */
} variants[] = {
	/* hdr is base64url of {"alg":"ML-DSA-NN","typ":"JWT"} */
	{ "mldsa_key_44.json", "mldsa_key_44_pub.json", JWT_ALG_ML_DSA_44,
	  "eyJhbGciOiJNTC1EU0EtNDQiLCJ0eXAiOiJKV1QifQ" },
	{ "mldsa_key_65.json", "mldsa_key_65_pub.json", JWT_ALG_ML_DSA_65,
	  "eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ" },
	{ "mldsa_key_87.json", "mldsa_key_87_pub.json", JWT_ALG_ML_DSA_87,
	  "eyJhbGciOiJNTC1EU0EtODciLCJ0eXAiOiJKV1QifQ" },
};

/* Build a token with the private key, verify it with the public key. ML-DSA is
 * OpenSSL-only for now, so the test is meaningful only on that backend; the
 * other backends are exercised by test_mldsa_unsupported below. */
START_TEST(test_mldsa_sign_verify)
{
	size_t i;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	for (i = 0; i < ARRAY_SIZE(variants); i++) {
		jwk_set_auto_t *pset = NULL, *vset = NULL;
		jwt_builder_auto_t *builder = NULL;
		jwt_checker_auto_t *checker = NULL;
		const jwk_item_t *priv, *pub;
		char_auto *token = NULL;
		char *path;
		int ret;

		/* --- load the private (signing) key --- */
		ret = asprintf(&path, KEYDIR "/%s", variants[i].priv);
		ck_assert_int_gt(ret, 0);
		pset = jwks_create_fromfile(path);
		free(path);
		ck_assert_ptr_nonnull(pset);
		ck_assert_int_eq(jwks_error(pset), 0);

		priv = jwks_item_get(pset, 0);
		ck_assert_ptr_nonnull(priv);
		ck_assert_int_eq(jwks_item_error(priv), 0);
		ck_assert_int_eq(jwks_item_kty(priv), JWK_KEY_TYPE_AKP);
		ck_assert_int_eq(jwks_item_alg(priv), variants[i].alg);
		ck_assert_int_eq(jwks_item_is_private(priv), 1);

		/* --- sign --- */
		builder = jwt_builder_new();
		ck_assert_ptr_nonnull(builder);
		ret = jwt_builder_setkey(builder, variants[i].alg, priv);
		ck_assert_int_eq(ret, 0);

		token = jwt_builder_generate(builder);
		if (token == NULL)
			fprintf(stderr, "BuildErr[%s]: %s\n",
				jwt_alg_str(variants[i].alg),
				jwt_builder_error_msg(builder));
		ck_assert_ptr_nonnull(token);

		/* The emitted protected header must carry the exact JOSE alg
		 * name: assert the first compact segment, so a wrong/missing
		 * "alg" string is caught even when both sides agree. */
		ck_assert(!strncmp(token, variants[i].hdr,
				   strlen(variants[i].hdr)));
		ck_assert_int_eq(token[strlen(variants[i].hdr)], '.');

		/* --- load the public (verifying) key and verify --- */
		ret = asprintf(&path, KEYDIR "/%s", variants[i].pub);
		ck_assert_int_gt(ret, 0);
		vset = jwks_create_fromfile(path);
		free(path);
		ck_assert_ptr_nonnull(vset);
		ck_assert_int_eq(jwks_error(vset), 0);

		pub = jwks_item_get(vset, 0);
		ck_assert_ptr_nonnull(pub);
		ck_assert_int_eq(jwks_item_is_private(pub), 0);

		checker = jwt_checker_new();
		ck_assert_ptr_nonnull(checker);
		ret = jwt_checker_setkey(checker, variants[i].alg, pub);
		ck_assert_int_eq(ret, 0);

		ret = jwt_checker_verify(checker, token);
		if (ret)
			fprintf(stderr, "CheckErr[%s]: %s\n",
				jwt_alg_str(variants[i].alg),
				jwt_checker_error_msg(checker));
		ck_assert_int_eq(ret, 0);
	}
}
END_TEST

/* A token signed for one variant must not verify against another variant's
 * key (anti algorithm-confusion). The configured alg (from the key) differs
 * from the token's header alg, so the checker rejects it. */
START_TEST(test_mldsa_cross_variant)
{
	jwk_set_auto_t *pset = NULL, *vset = NULL;
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	char *path;
	int ret;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	/* Sign with ML-DSA-44. */
	ret = asprintf(&path, KEYDIR "/mldsa_key_44.json");
	ck_assert_int_gt(ret, 0);
	pset = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(pset);
	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwt_builder_setkey(builder, JWT_ALG_ML_DSA_44,
				 jwks_item_get(pset, 0));
	ck_assert_int_eq(ret, 0);
	token = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(token);

	/* Verify with the ML-DSA-87 public key: must fail. */
	ret = asprintf(&path, KEYDIR "/mldsa_key_87_pub.json");
	ck_assert_int_gt(ret, 0);
	vset = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(vset);
	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwt_checker_setkey(checker, JWT_ALG_ML_DSA_87,
				 jwks_item_get(vset, 0));
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

#if defined(HAVE_GNUTLS) || defined(HAVE_MBEDTLS)
/* Backends without ML-DSA (GnuTLS, MbedTLS today) must reject an AKP JWK
 * cleanly at parse time via the common null-guard, not crash. Only built when
 * such a backend is compiled in, so it never vacuously passes. */
START_TEST(test_mldsa_unsupported)
{
	jwk_set_auto_t *set = NULL;
	const jwk_item_t *item;
	char *path;
	int ret;

	SET_OPS();

	if (jwt_test_ops[_i].type == JWT_CRYPTO_OPS_OPENSSL)
		return;

	ret = asprintf(&path, KEYDIR "/mldsa_key_44.json");
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	/* The kty is recognized as AKP, but the active backend cannot use it. */
	ck_assert_int_ne(jwks_item_error(item), 0);
	ck_assert_ptr_nonnull(strstr(jwks_item_error_msg(item), "ML-DSA"));
}
END_TEST
#endif /* HAVE_GNUTLS || HAVE_MBEDTLS */

/* Malformed AKP JWKs must be rejected with an item error (OpenSSL backend,
 * which is where process_mldsa actually runs). */
START_TEST(test_mldsa_parse_errors)
{
	static const char *bad[] = {
		/* "alg" is required on AKP keys */
		"{\"kty\":\"AKP\",\"pub\":\"AAAA\"}",
		/* non-string "alg" */
		"{\"kty\":\"AKP\",\"alg\":123,\"pub\":\"AAAA\"}",
		/* unsupported "alg" */
		"{\"kty\":\"AKP\",\"alg\":\"ML-DSA-99\",\"pub\":\"AAAA\"}",
		/* neither "pub" nor "priv" */
		"{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\"}",
		/* undecodable "pub" */
		"{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"\"}",
		/* undecodable "priv" (seed) */
		"{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"priv\":\"\"}",
	};
	size_t i;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwk_set_auto_t *set = jwks_create(bad[i]);
		const jwk_item_t *item;

		ck_assert_ptr_nonnull(set);
		item = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwks_item_error(item), 0);
	}
}
END_TEST

/* Native key (PEM/DER) -> JWK export, public stripping, and re-import.
 * Exercises the OpenSSL key2jwk export path for ML-DSA. */
START_TEST(test_mldsa_export)
{
	static const char *pems[] = {
		"mldsa_key_44.pem", "mldsa_key_65.pem", "mldsa_key_87.pem",
	};
	size_t i;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	for (i = 0; i < ARRAY_SIZE(pems); i++) {
		jwk_set_auto_t *set = NULL, *round = NULL;
		char_auto *priv_json = NULL, *pub_json = NULL;
		const jwk_item_t *item;
		char *path;
		int ret;

		ret = asprintf(&path, KEYDIR "/mldsa-pem/%s", pems[i]);
		ck_assert_int_gt(ret, 0);
		set = jwks_create_fromkey_file(path, JWK_KEY_NONE);
		free(path);
		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);

		item = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_eq(jwks_item_error(item), 0);
		ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_AKP);
		ck_assert_int_eq(jwks_item_is_private(item), 1);

		/* Private export keeps "pub" and "priv"; public strips "priv". */
		priv_json = jwks_item_export(item, 1);
		pub_json = jwks_item_export(item, 0);
		ck_assert_ptr_nonnull(priv_json);
		ck_assert_ptr_nonnull(pub_json);
		ck_assert_ptr_nonnull(strstr(priv_json, "\"pub\""));
		ck_assert_ptr_nonnull(strstr(priv_json, "\"priv\""));
		ck_assert_ptr_nonnull(strstr(pub_json, "\"pub\""));
		ck_assert_ptr_null(strstr(pub_json, "\"priv\""));

		/* Members must be base64url (no +, /, or = padding). */
		ck_assert_ptr_null(strchr(priv_json, '+'));
		ck_assert_ptr_null(strchr(priv_json, '/'));
		ck_assert_ptr_null(strchr(priv_json, '='));

		/* The private export must re-import to a usable private key. */
		round = jwks_create(priv_json);
		ck_assert_ptr_nonnull(round);
		ck_assert_int_eq(jwks_error(round), 0);
		item = jwks_item_get(round, 0);
		ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_AKP);
		ck_assert_int_eq(jwks_item_is_private(item), 1);
	}
}
END_TEST

/* An ML-DSA private key that retains no FIPS-204 seed (e.g. imported from only
 * the expanded private key) cannot be expressed as a private AKP JWK. It must
 * downgrade to a clean public export, NOT a private-marked JWK with no "priv". */
START_TEST(test_mldsa_export_seedless)
{
	jwk_set_auto_t *set = NULL;
	char_auto *priv_json = NULL;
	const jwk_item_t *item;
	char *path;
	int ret;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	ret = asprintf(&path, KEYDIR "/mldsa-pem/mldsa_key_44_seedless.pem");
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromkey_file(path, JWK_KEY_NONE);
	free(path);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);

	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_AKP);
	/* Downgraded to public: no private material, so not marked private. */
	ck_assert_int_eq(jwks_item_is_private(item), 0);

	/* Even a "private" export must not invent a "priv" it does not have. */
	priv_json = jwks_item_export(item, 1);
	ck_assert_ptr_nonnull(priv_json);
	ck_assert_ptr_nonnull(strstr(priv_json, "\"pub\""));
	ck_assert_ptr_null(strstr(priv_json, "\"priv\""));
}
END_TEST

/* DER and PEM of the same key must export to identical JWK JSON. */
START_TEST(test_mldsa_der_matches_pem)
{
	static const char *pairs[][2] = {
		{ "mldsa_key_44.pem",     "mldsa_key_44.der" },
		{ "mldsa_key_44_pub.pem", "mldsa_key_44_pub.der" },
	};
	size_t i;

	SET_OPS();

	if (jwt_test_ops[_i].type != JWT_CRYPTO_OPS_OPENSSL)
		return;

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		jwk_set_auto_t *pset = NULL, *dset = NULL;
		char_auto *pjson = NULL, *djson = NULL;
		char *path;
		int ret;

		ret = asprintf(&path, KEYDIR "/mldsa-pem/%s", pairs[i][0]);
		ck_assert_int_gt(ret, 0);
		pset = jwks_create_fromkey_file(path, JWK_KEY_NONE);
		free(path);

		ret = asprintf(&path, KEYDIR "/mldsa-pem/%s", pairs[i][1]);
		ck_assert_int_gt(ret, 0);
		dset = jwks_create_fromkey_file(path, JWK_KEY_NONE);
		free(path);

		ck_assert_ptr_nonnull(pset);
		ck_assert_ptr_nonnull(dset);
		ck_assert_int_eq(jwks_error(pset), 0);
		ck_assert_int_eq(jwks_error(dset), 0);

		pjson = jwks_export(pset, 1);
		djson = jwks_export(dset, 1);
		ck_assert_ptr_nonnull(pjson);
		ck_assert_ptr_nonnull(djson);
		ck_assert_str_eq(pjson, djson);
	}
}
END_TEST

#else /* !LIBJWT_HAVE_ML_DSA */

/* Built without ML-DSA support; keep one trivially-passing test so the binary
 * is non-empty and clearly reports the feature as not built in. */
START_TEST(test_mldsa_disabled)
{
	ck_assert(1);
}
END_TEST

#endif

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create(title);
	tc_core = tcase_create("ML-DSA");

#ifdef LIBJWT_HAVE_ML_DSA
	{
		int i = ARRAY_SIZE(jwt_test_ops);

		tcase_add_loop_test(tc_core, test_mldsa_sign_verify, 0, i);
		tcase_add_loop_test(tc_core, test_mldsa_cross_variant, 0, i);
#if defined(HAVE_GNUTLS) || defined(HAVE_MBEDTLS)
		tcase_add_loop_test(tc_core, test_mldsa_unsupported, 0, i);
#endif
		tcase_add_loop_test(tc_core, test_mldsa_parse_errors, 0, i);
		tcase_add_loop_test(tc_core, test_mldsa_export, 0, i);
		tcase_add_loop_test(tc_core, test_mldsa_export_seedless, 0, i);
		tcase_add_loop_test(tc_core, test_mldsa_der_matches_pem, 0, i);
	}
#else
	tcase_add_test(tc_core, test_mldsa_disabled);
#endif

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT ML-DSA (FIPS 204)");
}
