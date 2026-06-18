/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7515,7.2} JWS JSON Serialization (multi-signature) + keyring/policy
 * verification (issue #308). Every test runs under each compiled crypto backend
 * via the SET_OPS() loop, and the suite is built under both JSON backends. */

/* Private signing keys in tests/keys/jwks_keyring.json (used for kid tests). */
#define KID_ES256 "ee30e68c-a5e9-4067-864e-cf7dc9ffd2c1"
#define KID_RS256 "1971c0aa-4369-435f-aaf3-d4ca34a23ddb"

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

/* A keyring of the standard EC P-256 + RSA-2048 private test keys (no kids; a
 * signature without a "kid" is matched by scanning the ring). */
static jwk_set_t *load_ec_rsa_ring(void)
{
	jwk_set_t *ring = jwks_create(NULL);

	ck_assert_ptr_nonnull(ring);
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/ec_key_prime256v1.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/rsa_key_2048.json"));
	ck_assert_uint_eq(jwks_item_count(ring), 2);

	return ring;
}

/* ---- Flattened round-trip, single key, across alg families ---- */
START_TEST(test_flat_roundtrip)
{
	static const struct {
		const char *file;
		jwt_alg_t alg;
	} cases[] = {
		{ "ec_key_prime256v1.json", JWT_ALG_ES256 },
		{ "rsa_key_2048.json",      JWT_ALG_RS256 },
		{ "oct_key_256.json",       JWT_ALG_HS256 },
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		jwt_builder_auto_t *builder = NULL;
		jwt_checker_auto_t *checker = NULL;
		char_auto *tok = NULL;
		jwk_set_t *ks = load_one(cases[i].file);
		const jwk_item_t *key = jwks_item_get(ks, 0);

		builder = jwt_builder_new();
		ck_assert_int_eq(jwt_builder_setkey(builder, cases[i].alg, key), 0);
		ck_assert_int_eq(jwt_builder_set_format(builder,
			JWT_FORMAT_JSON_FLAT), 0);
		tok = jwt_builder_generate(builder);
		ck_assert_ptr_nonnull(tok);
		ck_assert_int_eq(tok[0], '{');	/* it is JSON, not compact */

		checker = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(checker, cases[i].alg, key), 0);
		ck_assert_int_eq(jwt_checker_verify(checker, tok), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(checker), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(checker, 0), 1);

		jwks_free(ks);
	}
}
END_TEST

/* ---- General round-trip: RS256 + ES256, verified against a 2-key ring ---- */
START_TEST(test_general_roundtrip)
{
	jwt_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;
	jwk_set_t *eks, *rks, *ring;
	const jwk_item_t *ec, *rsa;
	jwt_verify_policy_t pol[] = { JWT_VERIFY_POLICY_ANY, JWT_VERIFY_POLICY_ALL };
	size_t i;

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	rks = load_one("rsa_key_2048.json");
	ec = jwks_item_get(eks, 0);
	rsa = jwks_item_get(rks, 0);
	ring = load_ec_rsa_ring();

	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_RS256, rsa), 0);
	ck_assert_ptr_nonnull(jwt_builder_add_signature(builder, JWT_ALG_ES256, ec));
	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	/* Both ANY and ALL accept: every signature verifies against the ring. */
	for (i = 0; i < ARRAY_SIZE(pol); i++) {
		jwt_checker_auto_t *checker = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(checker, ring, pol[i]), 0);
		ck_assert_int_eq(jwt_checker_verify(checker, tok), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(checker), 2);
		ck_assert_int_eq(jwt_checker_sig_verified(checker, 0), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(checker, 1), 1);
		ck_assert_ptr_nonnull(jwt_checker_sig_key(checker, 0));
	}

	jwks_free(eks);
	jwks_free(rks);
	jwks_free(ring);
}
END_TEST

/* ---- Policy: a ring missing one signer's key. ANY passes, ALL fails. ---- */
START_TEST(test_policy_partial_ring)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *c_any = NULL, *c_all = NULL;
	char_auto *tok = NULL;
	jwk_set_t *eks, *rks, *ring;
	const jwk_item_t *ec, *rsa;

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	rks = load_one("rsa_key_2048.json");
	ec = jwks_item_get(eks, 0);
	rsa = jwks_item_get(rks, 0);

	/* Ring with ONLY the EC key. */
	ring = jwks_create(NULL);
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/ec_key_prime256v1.json"));

	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_RS256, rsa), 0);
	ck_assert_ptr_nonnull(jwt_builder_add_signature(builder, JWT_ALG_ES256, ec));
	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	/* ANY: the ES256 signature verifies; the RS256 one has no key. */
	c_any = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c_any, ring,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c_any, tok), 0);
	ck_assert_int_eq(jwt_checker_sig_verified(c_any, 0), 0);	/* RS256 */
	ck_assert_int_eq(jwt_checker_sig_verified(c_any, 1), 1);	/* ES256 */

	/* ALL: not every signature verified -> reject. */
	c_all = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c_all, ring,
		JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_ne(jwt_checker_verify(c_all, tok), 0);

	jwks_free(eks);
	jwks_free(rks);
	jwks_free(ring);
}
END_TEST

/* ---- kid-driven key selection from a multi-key ring ---- */
START_TEST(test_kid_match)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	jwk_set_t *ring;
	jwk_item_t *ec, *rsa;
	jwt_signature_t *s_rsa, *s_ec;

	SET_OPS();

	ring = jwks_create_fromfile(KEYDIR "/jwks_keyring.json");
	ck_assert_ptr_nonnull(ring);
	ec = jwks_find_bykid(ring, KID_ES256);
	rsa = jwks_find_bykid(ring, KID_RS256);
	ck_assert_ptr_nonnull(ec);
	ck_assert_ptr_nonnull(rsa);

	/* Both signers added with add_signature so each can carry its own kid. */
	builder = jwt_builder_new();
	s_rsa = jwt_builder_add_signature(builder, JWT_ALG_RS256, rsa);
	ck_assert_ptr_nonnull(s_rsa);
	ck_assert_int_eq(jwt_signature_add_protected_json(s_rsa, "kid",
		"\"" KID_RS256 "\""), 0);
	s_ec = jwt_builder_add_signature(builder, JWT_ALG_ES256, ec);
	ck_assert_ptr_nonnull(s_ec);
	ck_assert_int_eq(jwt_signature_add_protected_json(s_ec, "kid",
		"\"" KID_ES256 "\""), 0);

	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(checker, ring,
		JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, tok), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(checker), 2);
	/* Each signature verified against the key its kid named. */
	ck_assert_str_eq(jwks_item_kid(jwt_checker_sig_key(checker, 0)), KID_RS256);
	ck_assert_str_eq(jwks_item_kid(jwt_checker_sig_key(checker, 1)), KID_ES256);

	jwks_free(ring);
}
END_TEST

/* ---- Tampering a signature is rejected ---- */
START_TEST(test_tamper)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	jwk_set_t *eks;
	const jwk_item_t *ec;
	char *p;

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(eks, 0);

	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_set_format(builder, JWT_FORMAT_JSON_FLAT), 0);
	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	/* Flip the first base64url char of the signature. */
	p = strstr(tok, "\"signature\":\"");
	ck_assert_ptr_nonnull(p);
	p += strlen("\"signature\":\"");
	*p = (*p == 'A') ? 'B' : 'A';

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, ec), 0);
	ck_assert_int_ne(jwt_checker_verify(checker, tok), 0);

	jwks_free(eks);
}
END_TEST

/* ---- Malformed JSON serializations are rejected, never crash (json-c) ---- */
START_TEST(test_malformed)
{
	/* "e30" is base64url({}). Each of these must be rejected structurally. */
	static const char * const bad[] = {
		"{}",						/* no payload */
		"{\"payload\":123}",				/* non-string payload */
		"{\"payload\":\"e30\"}",			/* no signature(s) */
		"{\"payload\":\"e30\",\"signatures\":[]}",	/* empty array */
		"{\"payload\":\"e30\",\"signatures\":\"x\"}",	/* non-array */
		/* both General and Flattened members */
		"{\"payload\":\"e30\",\"signatures\":[{\"protected\":\"e30\","
			"\"signature\":\"x\"}],\"signature\":\"y\"}",
		/* flattened, missing signature */
		"{\"payload\":\"e30\",\"protected\":\"e30\"}",
		/* alg:none in protected (base64url of {"alg":"none"}) */
		"{\"payload\":\"e30\",\"protected\":\"eyJhbGciOiJub25lIn0\","
			"\"signature\":\"\"}",
		"{ this is not json",
	};
	jwk_set_t *eks;
	const jwk_item_t *ec;
	size_t i;

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(eks, 0);

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwt_checker_auto_t *checker = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256, ec), 0);
		ck_assert_int_ne(jwt_checker_verify(checker, bad[i]), 0);
	}

	jwks_free(eks);
}
END_TEST

/* ---- "none" is refused on the builder side too ---- */
START_TEST(test_none_rejected_builder)
{
	jwt_builder_auto_t *builder = jwt_builder_new();

	SET_OPS();

	ck_assert_ptr_null(jwt_builder_add_signature(builder, JWT_ALG_NONE, NULL));
}
END_TEST

static int cb_allow(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	(void)config;
	return 0;
}

static int cb_reject(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	(void)config;
	return 1;
}

/* ---- Per-signature unprotected header + assorted edge/error paths ---- */
START_TEST(test_edges)
{
	jwt_builder_auto_t *b1 = NULL, *b2 = NULL, *b3 = NULL;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
	jwt_signature_t *sig;
	char_auto *tok = NULL;
	jwk_set_t *eks;
	const jwk_item_t *ec;

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(eks, 0);

	/* (a) An unprotected per-signature "header" round-trips and verifies. */
	b1 = jwt_builder_new();
	sig = jwt_builder_add_signature(b1, JWT_ALG_ES256, ec);
	ck_assert_ptr_nonnull(sig);
	ck_assert_int_eq(jwt_signature_add_header_json(sig, "kid", "\"hint\""), 0);
	ck_assert_int_eq(jwt_builder_set_format(b1, JWT_FORMAT_JSON_FLAT), 0);
	tok = jwt_builder_generate(b1);
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "\"header\""));

	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, tok), 0);
	/* Out-of-range introspection is safe. */
	ck_assert_int_eq(jwt_checker_sig_verified(c1, 99), 0);
	ck_assert_ptr_null(jwt_checker_sig_key(c1, 99));

	/* (b) A header parameter in both protected and unprotected is rejected. */
	b2 = jwt_builder_new();
	sig = jwt_builder_add_signature(b2, JWT_ALG_ES256, ec);
	ck_assert_int_eq(jwt_signature_add_protected_json(sig, "kid", "\"a\""), 0);
	ck_assert_int_eq(jwt_signature_add_header_json(sig, "kid", "\"b\""), 0);
	ck_assert_int_eq(jwt_builder_set_format(b2, JWT_FORMAT_JSON_FLAT), 0);
	ck_assert_ptr_null(jwt_builder_generate(b2));

	/* (c) "none" cannot be emitted in a JSON serialization. */
	b3 = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b3, JWT_ALG_NONE, NULL), 0);
	ck_assert_int_eq(jwt_builder_set_format(b3, JWT_FORMAT_JSON_FLAT), 0);
	ck_assert_ptr_null(jwt_builder_generate(b3));

	/* (d) A verify callback runs per signature: allow then reject. */
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_setcb(c2, cb_allow, NULL), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, tok), 0);

	c3 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c3, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_setcb(c3, cb_reject, NULL), 0);
	ck_assert_int_ne(jwt_checker_verify(c3, tok), 0);

	/* (e) setkeyring rejects a NULL ring and a bogus policy. */
	{
		jwt_checker_auto_t *c4 = jwt_checker_new();

		ck_assert_int_ne(jwt_checker_setkeyring(c4, NULL,
			JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_ne(jwt_checker_setkeyring(c4, eks,
			(jwt_verify_policy_t)42), 0);
	}

	jwks_free(eks);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jws_json");

	tcase_add_loop_test(tc_core, test_flat_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, test_general_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, test_policy_partial_ring, 0, i);
	tcase_add_loop_test(tc_core, test_kid_match, 0, i);
	tcase_add_loop_test(tc_core, test_tamper, 0, i);
	tcase_add_loop_test(tc_core, test_malformed, 0, i);
	tcase_add_loop_test(tc_core, test_none_rejected_builder, 0, i);
	tcase_add_loop_test(tc_core, test_edges, 0, i);

	tcase_set_timeout(tc_core, 60);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWS JSON Serialization (#308)");
}
