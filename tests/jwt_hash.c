/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for jwt_token_hash() (DPoP "ath", the full digest) and
 * jwt_token_hash_half() (OIDC "at_hash"/"c_hash", the left half keyed to the
 * signing alg). The anchors are the published OpenID Connect Core 3.1.3.6
 * at_hash example and a full SHA-256 vector. SET_OPS() runs each across every
 * compiled crypto backend, so each backend's one-shot SHA is exercised. */

/* OIDC Core 3.1.3.6: at_hash of this access token under an RS256 (SHA-256) ID
 * token. The value is the left half of the digest, base64url. */
#define OIDC_AT		"jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
#define OIDC_ATHASH	"77QmUPtjPfzWtF2AnpK9RQ"

START_TEST(test_at_hash_oidc_vector)
{
	char_auto *h = NULL;

	SET_OPS();

	h = jwt_token_hash_half(OIDC_AT, JWT_ALG_RS256);
	ck_assert_ptr_nonnull(h);
	ck_assert_str_eq(h, OIDC_ATHASH);
}
END_TEST

/* DPoP "ath" = FULL base64url(SHA-256(access_token)). */
START_TEST(test_ath_full_vector)
{
	char_auto *h = NULL;

	SET_OPS();

	h = jwt_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			   JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(h);
	ck_assert_str_eq(h, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
}
END_TEST

START_TEST(test_full_lengths_and_determinism)
{
	char_auto *a = NULL, *b = NULL;
	char_auto *c256 = NULL, *c384 = NULL, *c512 = NULL;

	SET_OPS();

	/* base64url of a 32/48/64-byte digest = 43/64/86 chars (no padding). */
	c256 = jwt_token_hash("hello", JWK_THUMBPRINT_SHA256);
	c384 = jwt_token_hash("hello", JWK_THUMBPRINT_SHA384);
	c512 = jwt_token_hash("hello", JWK_THUMBPRINT_SHA512);
	ck_assert_ptr_nonnull(c256);
	ck_assert_ptr_nonnull(c384);
	ck_assert_ptr_nonnull(c512);
	ck_assert_int_eq((int)strlen(c256), 43);
	ck_assert_int_eq((int)strlen(c384), 64);
	ck_assert_int_eq((int)strlen(c512), 86);

	/* Deterministic; different inputs differ. */
	a = jwt_token_hash("hello", JWK_THUMBPRINT_SHA256);
	b = jwt_token_hash("world", JWK_THUMBPRINT_SHA256);
	ck_assert_str_eq(a, c256);
	ck_assert_str_ne(a, b);
}
END_TEST

START_TEST(test_half_is_left_half)
{
	char_auto *full = NULL, *half = NULL;

	SET_OPS();

	/* RS256 -> SHA-256; the half is 16 bytes -> 22 chars and is the leading
	 * bytes of the full digest, so the first five base64url groups (15 bytes
	 * -> 20 chars) are shared with the full encoding. */
	full = jwt_token_hash("hello", JWK_THUMBPRINT_SHA256);
	half = jwt_token_hash_half("hello", JWT_ALG_RS256);
	ck_assert_ptr_nonnull(half);
	ck_assert_int_eq((int)strlen(half), 22);
	ck_assert(!strncmp(full, half, 20));
}
END_TEST

START_TEST(test_half_alg_widths)
{
	char_auto *h256 = NULL, *h384 = NULL, *h512 = NULL, *hed = NULL;

	SET_OPS();

	h256 = jwt_token_hash_half("hello", JWT_ALG_ES256);
	h384 = jwt_token_hash_half("hello", JWT_ALG_ES384);
	h512 = jwt_token_hash_half("hello", JWT_ALG_ES512);
	hed  = jwt_token_hash_half("hello", JWT_ALG_EDDSA);
	ck_assert_int_eq((int)strlen(h256), 22);	/* 16 bytes */
	ck_assert_int_eq((int)strlen(h384), 32);	/* 24 bytes */
	ck_assert_int_eq((int)strlen(h512), 43);	/* 32 bytes */
	ck_assert_int_eq((int)strlen(hed),  43);	/* EdDSA -> SHA-512 -> 32 */
}
END_TEST

START_TEST(test_errors)
{
	SET_OPS();

	ck_assert_ptr_null(jwt_token_hash(NULL, JWK_THUMBPRINT_SHA256));
	ck_assert_ptr_null(jwt_token_hash_half(NULL, JWT_ALG_ES256));
	/* An alg with no SHA-2 width -> NULL. */
	ck_assert_ptr_null(jwt_token_hash_half("hello", JWT_ALG_NONE));
	ck_assert_ptr_null(jwt_token_hash_half("hello", JWT_ALG_INVAL));
	/* An out-of-range thumbprint selector -> NULL. */
	ck_assert_ptr_null(jwt_token_hash("hello", (jwk_thumbprint_alg_t)999));
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_hash");

	tcase_add_loop_test(tc_core, test_at_hash_oidc_vector, 0, i);
	tcase_add_loop_test(tc_core, test_ath_full_vector, 0, i);
	tcase_add_loop_test(tc_core, test_full_lengths_and_determinism, 0, i);
	tcase_add_loop_test(tc_core, test_half_is_left_half, 0, i);
	tcase_add_loop_test(tc_core, test_half_alg_widths, 0, i);
	tcase_add_loop_test(tc_core, test_errors, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT token hash (ath / at_hash / c_hash)");
}
