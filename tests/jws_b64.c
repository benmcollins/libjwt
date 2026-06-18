/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7797} JWS unencoded ("b64":false) + detached payloads (issue #315).
 * Runs under each compiled crypto backend (SET_OPS loop) and both JSON
 * backends. The Appendix A payload "$.02" is non-JSON on purpose. */

static const unsigned char RAW[] = "$.02";
#define RAW_LEN 4

static jwk_set_t *load_one(const char *file)
{
	char *path;
	jwk_set_t *set;
	int ret;

	ret = asprintf(&path, KEYDIR "/%s", file);
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

static const jwt_serialization_t formats[] = {
	JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT, JWT_FORMAT_JSON_GENERAL,
};

/* ---- b64=false, attached, every serialization ---- */
START_TEST(test_b64_false_attached)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t f;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(formats); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[f]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- b64=false, detached, every serialization ---- */
START_TEST(test_b64_false_detached)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t f;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(formats); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[f]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		/* Correct out-of-band payload verifies; a wrong one is rejected. */
		ck_assert_int_eq(jwt_checker_verify_detached(c, tok, RAW, RAW_LEN), 0);
		ck_assert_int_ne(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)"x.99", 4), 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- b64=true detached JSON claims (a detached JWT, RFC 7515 App F) ---- */
START_TEST(test_b64_true_detached_jwt)
{
	static const unsigned char JSON[] = "{\"sub\":\"alice\"}";
	jwk_set_t *ks;
	const jwk_item_t *ec;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_setpayload(b, JSON, strlen((char *)JSON)), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_verify_detached(c, tok, JSON,
		strlen((char *)JSON)), 0);

	jwks_free(ks);
}
END_TEST

/* ---- RFC 7797 Appendix A.4: HS256, detached, unencoded "$.02" ---- */
START_TEST(test_rfc7797_appendix_a)
{
	/* The HMAC key from RFC 7515 Appendix A.1. */
	static const char *KEY =
		"{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ"
		"-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
	/* The detached JWS from RFC 7797 Appendix A.4. */
	static const char *TOKEN =
		"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
		"..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";
	jwk_set_t *ks;
	const jwk_item_t *k;
	jwt_checker_auto_t *c = NULL, *c2 = NULL;

	SET_OPS();

	ks = jwks_create(NULL);
	ck_assert_ptr_nonnull(ks);
	ck_assert_ptr_nonnull(jwks_load(ks, KEY));
	k = jwks_item_get(ks, 0);
	ck_assert_ptr_nonnull(k);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256, k), 0);
	ck_assert_int_eq(jwt_checker_verify_detached(c, TOKEN, RAW, RAW_LEN), 0);

	/* A different payload must not verify against the RFC signature. */
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_HS256, k), 0);
	ck_assert_int_ne(jwt_checker_verify_detached(c2, TOKEN,
		(const unsigned char *)"$.03", 4), 0);

	jwks_free(ks);
}
END_TEST

/* ---- Security + builder guards ---- */
START_TEST(test_b64_security)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	/* base64url({"alg":"ES256","b64":false}) -- b64 NOT in crit. */
	static const char *NOCRIT =
		"eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2V9.$.02.AAAA";

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* @rfc{7797,6} b64=false without "b64" in "crit" is rejected. */
	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_ne(jwt_checker_verify(c, NOCRIT), 0);

	/* The builder refuses b64=false without a raw payload (would be a JWT). */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	ck_assert_ptr_null(jwt_builder_generate(b));

	/* An unencoded payload with an embedded NUL cannot be serialized verbatim,
	 * so it is rejected rather than silently truncated. */
	{
		jwt_builder_auto_t *bn = jwt_builder_new();
		static const unsigned char NUL_PT[] = { 'a', '\0', 'b' };

		ck_assert_int_eq(jwt_builder_setkey(bn, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(bn, NUL_PT, 3), 0);
		ck_assert_int_eq(jwt_builder_setb64(bn, 0), 0);
		ck_assert_ptr_null(jwt_builder_generate(bn));
	}

	jwks_free(ks);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jws_b64");

	tcase_add_loop_test(tc_core, test_b64_false_attached, 0, i);
	tcase_add_loop_test(tc_core, test_b64_false_detached, 0, i);
	tcase_add_loop_test(tc_core, test_b64_true_detached_jwt, 0, i);
	tcase_add_loop_test(tc_core, test_rfc7797_appendix_a, 0, i);
	tcase_add_loop_test(tc_core, test_b64_security, 0, i);

	tcase_set_timeout(tc_core, 60);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT RFC 7797 unencoded/detached payload (#315)");
}
