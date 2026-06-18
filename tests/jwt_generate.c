/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* jwks_generate() key generation (issue #311). Runs under each compiled crypto
 * backend (SET_OPS) and both JSON backends. Backends differ in capability
 * (MbedTLS has no EdDSA/ML-DSA; GnuTLS no secp256k1/X-curves), so the
 * "optional" types are probed: a clean error is accepted, a success is verified.
 */

/* Generate, then (for a signing alg) round-trip sign+verify the new key.
 * Returns 1 if generated OK, 0 if the backend reported it unsupported. */
static int gen_check(jwk_key_type_t kty, const char *param, jwt_alg_t alg,
		     unsigned int flags, int can_sign)
{
	jwk_set_t *set;
	const jwk_item_t *k;
	int ok;

	set = jwks_create_generate(kty, param, alg, flags);
	ck_assert_ptr_nonnull(set);

	k = jwks_item_get(set, 0);
	if (k == NULL || jwks_item_error(k)) {
		/* Capability-gated on this backend: must be a clean error. */
		ck_assert(jwks_error(set) || (k && jwks_item_error(k)));
		jwks_free(set);
		return 0;
	}

	ck_assert_int_eq(jwks_item_kty(k), kty);
	ck_assert_int_eq(jwks_item_is_private(k), 1);

	if (flags & JWK_KEY_GEN_KID)
		ck_assert_ptr_nonnull(jwks_item_kid(k));
	else
		ck_assert_ptr_null(jwks_item_kid(k));

	if (can_sign) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_int_eq(jwt_builder_setkey(b, alg, k), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);
		ck_assert_int_eq(jwt_checker_setkey(c, alg, k), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	}

	ok = 1;
	jwks_free(set);

	return ok;
}

/* Core types every backend must support. */
START_TEST(test_generate_core)
{
	SET_OPS();

	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_EC, "P-256", JWT_ALG_ES256,
				   JWK_KEY_GEN_KID, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_EC, "P-384", JWT_ALG_ES384,
				   JWK_KEY_GEN_KID, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_EC, "P-521", JWT_ALG_ES512,
				   JWK_KEY_GEN_KID, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_RSA, "2048", JWT_ALG_RS256,
				   JWK_KEY_GEN_KID, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_RSA, "2048", JWT_ALG_PS256,
				   JWK_KEY_GEN_KID, 1), 1);
	/* The in-key PEM cannot encode PS384 vs PS256; the override must stick. */
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_RSA, "3072", JWT_ALG_PS384,
				   0, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_OCT, "256", JWT_ALG_HS256,
				   JWK_KEY_GEN_KID, 1), 1);
	ck_assert_int_eq(gen_check(JWK_KEY_TYPE_OCT, "512", JWT_ALG_HS512,
				   0, 1), 1);
}
END_TEST

/* Capability-dependent types: a clean error or a verified key, never a crash. */
START_TEST(test_generate_optional)
{
	SET_OPS();

	gen_check(JWK_KEY_TYPE_EC, "secp256k1", JWT_ALG_ES256K, JWK_KEY_GEN_KID, 1);
	gen_check(JWK_KEY_TYPE_OKP, "Ed25519", JWT_ALG_EDDSA, JWK_KEY_GEN_KID, 1);
	gen_check(JWK_KEY_TYPE_OKP, "Ed448", JWT_ALG_EDDSA, 0, 1);
	gen_check(JWK_KEY_TYPE_OKP, "X25519", JWT_ALG_NONE, 0, 0);
	/* AKP/ML-DSA where a capable backend (OpenSSL >= 3.5 / GnuTLS+leancrypto)
	 * is present; a clean error elsewhere. */
	gen_check(JWK_KEY_TYPE_AKP, NULL, JWT_ALG_ML_DSA_44, JWK_KEY_GEN_KID, 1);
	gen_check(JWK_KEY_TYPE_AKP, NULL, JWT_ALG_ML_DSA_65, 0, 1);
	gen_check(JWK_KEY_TYPE_AKP, NULL, JWT_ALG_ML_DSA_87, 0, 1);
}
END_TEST

/* Bad requests are rejected cleanly (with an error set), never silently. */
START_TEST(test_generate_errors)
{
	struct { jwk_key_type_t kty; const char *param; jwt_alg_t alg; } bad[] = {
		{ JWK_KEY_TYPE_EC,  "P-256", JWT_ALG_RS256 },	/* alg<->kty */
		{ JWK_KEY_TYPE_RSA, "1024",  JWT_ALG_RS256 },	/* RSA too small */
		{ JWK_KEY_TYPE_RSA, "huge",  JWT_ALG_RS256 },	/* non-numeric */
		{ JWK_KEY_TYPE_EC,  "P-999", JWT_ALG_NONE },	/* unknown curve */
		{ JWK_KEY_TYPE_OCT, "7",     JWT_ALG_NONE },	/* not multiple of 8 */
		{ JWK_KEY_TYPE_AKP, NULL,    JWT_ALG_NONE },	/* AKP needs a variant */
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwk_set_t *set = jwks_create_generate(bad[i].kty, bad[i].param,
						      bad[i].alg, 0);
		const jwk_item_t *k;

		ck_assert_ptr_nonnull(set);
		k = jwks_item_get(set, 0);
		/* Either a set-level error and no item, or an error item. */
		ck_assert(jwks_error(set) || (k != NULL && jwks_item_error(k)));
		ck_assert_int_eq(k == NULL || jwks_item_error(k), 1);
		jwks_free(set);
	}
}
END_TEST

/* Append to an existing keyring rather than replacing it. */
START_TEST(test_generate_append)
{
	jwk_set_t *set;

	SET_OPS();

	set = jwks_create_generate(JWK_KEY_TYPE_EC, "P-256", JWT_ALG_ES256, 0);
	ck_assert_ptr_nonnull(set);
	ck_assert_uint_eq(jwks_item_count(set), 1);

	ck_assert_ptr_eq(jwks_generate(set, JWK_KEY_TYPE_RSA, "2048",
				       JWT_ALG_RS256, 0), set);
	ck_assert_uint_eq(jwks_item_count(set), 2);

	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_generate");

	tcase_add_loop_test(tc_core, test_generate_core, 0, i);
	tcase_add_loop_test(tc_core, test_generate_optional, 0, i);
	tcase_add_loop_test(tc_core, test_generate_errors, 0, i);
	tcase_add_loop_test(tc_core, test_generate_append, 0, i);

	tcase_set_timeout(tc_core, 120);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT key generation (#311)");
}
