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

/* ====================================================================
 * GHSA-mhc9-xvg5-qg29: a keyring checker verifies a Compact token as the
 * equivalent one-signature JWS -- the same kid binding and kid-less scan,
 * alg/key-type binding, key "alg" pin, policy and per-signature callback as a
 * JSON token -- and never as an unkeyed checker that permits "none".
 * ==================================================================== */

/* Compact signers, each a private key file carrying its own "kid". */
#define CKID_HS256 "987cd169-c39c-42d4-a918-d444668a3ba7"
#define CKID_RS256 "28c243a4-a9ac-473f-ab61-d3a68f408279"
#define CKID_PS256 "a9a0eb5b-67e9-4495-9030-a97d063d4bb4"
#define CKID_ES256 "264265c2-4ef0-4751-adbd-9739550afe5b"
#define CKID_EDDSA "7dc4a07e-51b6-47dd-ae8c-2da0ef921818"

static const struct {
	const char *file;
	jwt_alg_t alg;
	const char *kid;
} ckeys[] = {
	{ "oct_key_256_issue1.json", JWT_ALG_HS256, CKID_HS256 },
	{ "rsa_key_2048.json",       JWT_ALG_RS256, CKID_RS256 },
	{ "rsa_pss_key_2048.json",   JWT_ALG_PS256, CKID_PS256 },
	{ "ec_key_prime256v1.json",  JWT_ALG_ES256, CKID_ES256 },
	{ "eddsa_key_ed25519.json",  JWT_ALG_EDDSA, CKID_EDDSA },
};
#define CKEYS_ALL ((1u << ARRAY_SIZE(ckeys)) - 1)

#define ERR_POLICY_1	"Signature policy not met (0 of 1 verified)"
#define ERR_BAD_ALG	"JWS signature has an invalid \"alg\""

/* Forged, UNSIGNED Compact tokens over attacker-chosen claims (EVIL =
 * {"sub":"admin","iss":"trusted","aud":"api"}): {"alg":"none"}; the same with
 * a "kid" naming a ring key ({"alg":"none","kid":CKID_RS256}); a junk
 * non-empty signature; and an empty claim set ("e30" = {}). */
#define NONE_HDR	"eyJhbGciOiJub25lIn0"
#define NONE_KID_HDR	"eyJhbGciOiJub25lIiwia2lkIjoiMjhjMjQzYTQtYTlhYy00" \
			"NzNmLWFiNjEtZDNhNjhmNDA4Mjc5In0"
#define EVIL		"eyJzdWIiOiJhZG1pbiIsImlzcyI6InRydXN0ZWQiLCJhdWQi" \
			"OiJhcGkifQ"

static const char * const forged_none[] = {
	NONE_HDR "." EVIL ".",
	NONE_KID_HDR "." EVIL ".",
	NONE_HDR "." EVIL ".AAAA",
	NONE_HDR ".e30.",
};

/* A ring of the ckeys[] whose index bit is set in @mask. */
static jwk_set_t *ckeys_ring(unsigned int mask)
{
	jwk_set_t *ring = jwks_create(NULL);
	size_t i;

	ck_assert_ptr_nonnull(ring);
	for (i = 0; i < ARRAY_SIZE(ckeys); i++) {
		char *path;

		if (!(mask & (1u << i)))
			continue;
		ck_assert_int_gt(asprintf(&path, KEYDIR "/%s", ckeys[i].file), 0);
		ck_assert_ptr_nonnull(jwks_load_fromfile(ring, path));
		free(path);
	}

	return ring;
}

/* A Compact token over {"sub":"alice"} signed by @key under @alg, with a "kid"
 * header when @kid is not NULL. NULL if the active backend cannot sign with
 * @key (EdDSA under MbedTLS), so the caller skips that case. */
static char *compact_tok(jwt_alg_t alg, const jwk_item_t *key, const char *kid)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, alg, key), 0);
	if (kid != NULL) {
		jwt_set_SET_STR(&v, "kid", kid);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
	}
	jwt_set_SET_STR(&v, "sub", "alice");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);

	return jwt_builder_generate(b);
}

static const jwt_verify_policy_t both_pol[] = {
	JWT_VERIFY_POLICY_ANY, JWT_VERIFY_POLICY_ALL,
};

/* ---- Compact + keyring: kid binding, kid-less scan, no fallback ---- */
START_TEST(test_compact_keyring)
{
	jwk_set_t *ring;
	size_t i, j, p;

	SET_OPS();
	ring = ckeys_ring(CKEYS_ALL);
	ck_assert_uint_eq(jwks_item_count(ring), ARRAY_SIZE(ckeys));

	for (i = 0; i < ARRAY_SIZE(ckeys); i++) {
		const jwk_item_t *key = jwks_find_bykid(ring, ckeys[i].kid);
		char_auto *kid_tok = NULL, *scan_tok = NULL, *miss_tok = NULL;
		jwk_set_t *others;

		ck_assert_ptr_nonnull(key);
		kid_tok = compact_tok(ckeys[i].alg, key, ckeys[i].kid);
		if (kid_tok == NULL)
			continue;	/* this backend cannot sign it */
		ck_assert_int_ne(kid_tok[0], '{');
		scan_tok = compact_tok(ckeys[i].alg, key, NULL);
		miss_tok = compact_tok(ckeys[i].alg, key, "not-in-the-ring");
		ck_assert_ptr_nonnull(scan_tok);
		ck_assert_ptr_nonnull(miss_tok);

		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
				both_pol[p]), 0);

			/* "kid" selects that ring key; one signature meets
			 * either policy. */
			ck_assert_int_eq(jwt_checker_verify(c, kid_tok), 0);
			ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
			ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), key);

			/* A kid-less token is tried against every compatible
			 * key. */
			ck_assert_int_eq(jwt_checker_verify(c, scan_tok), 0);
			ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
			ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), key);

			/* A "kid" not in the ring binds to nothing: there is no
			 * fallback to the scan, though the signer IS in it. */
			ck_assert_int_ne(jwt_checker_verify(c, miss_tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
			ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
			ck_assert_ptr_null(jwt_checker_sig_key(c, 0));
		}

		/* A "kid" naming another ring key binds to that key, which the
		 * alg/key-type binding (another family) or its "alg" pin (the
		 * other RSA key) refuses for this token. */
		for (j = 0; j < ARRAY_SIZE(ckeys); j++) {
			char_auto *x = NULL;

			if (j == i)
				continue;
			x = compact_tok(ckeys[i].alg, key, ckeys[j].kid);
			ck_assert_ptr_nonnull(x);
			for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
				jwt_checker_auto_t *c = jwt_checker_new();

				ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
					both_pol[p]), 0);
				ck_assert_int_ne(jwt_checker_verify(c, x), 0);
				ck_assert_str_eq(jwt_checker_error_msg(c),
						 ERR_POLICY_1);
			}
		}

		/* Without the signer, nothing else in the ring verifies it. */
		others = ckeys_ring(CKEYS_ALL & ~(1u << i));
		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_int_eq(jwt_checker_setkeyring(c, others,
				both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, scan_tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
		}
		jwks_free(others);
	}

	jwks_free(ring);
}
END_TEST

static int cb_count(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	(*(int *)config->ctx)++;
	return 0;
}

/* ---- A forged unsigned Compact token never passes a keyring checker ---- */
START_TEST(test_compact_keyring_none)
{
	static const unsigned char body[] = "{\"sub\":\"admin\"}";
	const char *req[] = { "sub", "iss" };
	jwk_set_t *ring;
	size_t i, p;
	int strict;

	SET_OPS();
	ring = ckeys_ring(CKEYS_ALL);

	for (i = 0; i < ARRAY_SIZE(forged_none); i++) {
		for (p = 0; p < 2 * ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();
			int calls = 0;

			strict = p % 2;
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
				both_pol[p / 2]), 0);
			if (strict) {
				/* Pins and requirements the forger's own claims
				 * satisfy, and a callback. */
				ck_assert_int_eq(jwt_checker_claim_set(c,
					JWT_CLAIM_ISS, "trusted"), 0);
				ck_assert_int_eq(jwt_checker_claim_set(c,
					JWT_CLAIM_AUD, "api"), 0);
				ck_assert_int_eq(jwt_checker_require(c, req, 2), 0);
				ck_assert_int_eq(jwt_checker_setcb(c, cb_count,
					&calls), 0);
			}

			ck_assert_int_ne(jwt_checker_verify(c, forged_none[i]), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_BAD_ALG);

			/* Refused while parsing: no signature recorded, none
			 * reported verified, and the callback never ran. */
			ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
			ck_assert_ptr_null(jwt_checker_sig_key(c, 0));
			ck_assert_int_eq(calls, 0);
		}
	}

	/* Detached ("<header>..") with any out-of-band payload. */
	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ring, both_pol[p]), 0);
		ck_assert_int_ne(jwt_checker_verify_detached(c, NONE_HDR "..",
			body, sizeof(body) - 1), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_BAD_ALG);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
	}

	jwks_free(ring);
}
END_TEST

/* GHSA-q843-6q5f-w55g shape: HS256 forgeries over EVIL, MACed with an empty key
 * or with the RSA public key's PEM (tests/keys/pem-files/rsa_key_2048_pub.pem),
 * kid-less and with a "kid" naming each RSA key of the ring. */
#define HS_HDR		"eyJhbGciOiJIUzI1NiJ9"
#define HS_HDR_NOALG	"eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYS1uby1hbGcifQ"
#define HS_HDR_MISLBL	"eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYS1taXNsYWJlbGVk" \
			"LWhzMjU2In0"

static const char * const forged_hs256[] = {
	HS_HDR "." EVIL ".3jrdM_vFcq3X8WeK1yN9cdNLqy8hccnJJr1P6PmxYL4",
	HS_HDR "." EVIL ".TO4I7J-DhBjso0yADP2E-ioWMsBUUcCF76zoMLren1M",
	HS_HDR_NOALG "." EVIL ".nAWQHtv-f6DzEG4e61VGJzvTlFbUdK1qYA0SShmfGnQ",
	HS_HDR_NOALG "." EVIL ".Z4GmsGOMRc4ZsmCSc4fFbF6ZU4fcsIMlIZ3Am0H5Shc",
	HS_HDR_MISLBL "." EVIL ".sMbJ6CRTs_6OWyxPc-CVxEaM-58hGSW0xASyEcNcJgs",
	HS_HDR_MISLBL "." EVIL ".tMi_4EsweSHTg-GBFO6QeODKBknvFCyTit3rFFSs7s8",
};

/* ---- RS256 vs a ring of RSA + oct keys: no algorithm confusion ---- */
START_TEST(test_compact_keyring_confusion)
{
	jwk_set_t *ring, *rks;
	const jwk_item_t *rsa_noalg;
	char_auto *rs = NULL, *rs_octkid = NULL;
	size_t i, p;

	SET_OPS();

	/* The RSA public key without an "alg" (the GHSA-q843 key), the same
	 * key with its "alg" mislabeled HS256, and an HS256 oct key. */
	ring = jwks_create(NULL);
	ck_assert_ptr_nonnull(ring);
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/rsa_key_2048_pub_no_alg.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/rsa_key_2048_pub_alg_hs256.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/oct_key_256_issue1.json"));
	ck_assert_uint_eq(jwks_item_count(ring), 3);
	rsa_noalg = jwks_find_bykid(ring, "rsa-no-alg");
	ck_assert_ptr_nonnull(rsa_noalg);

	rks = load_one("rsa_key_2048.json");
	rs = compact_tok(JWT_ALG_RS256, jwks_item_get(rks, 0), NULL);
	rs_octkid = compact_tok(JWT_ALG_RS256, jwks_item_get(rks, 0),
				CKID_HS256);
	ck_assert_ptr_nonnull(rs);
	ck_assert_ptr_nonnull(rs_octkid);

	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ring, both_pol[p]), 0);

		/* The genuine RS256 token verifies, and only against the RSA
		 * key (the mislabeled one is skipped by its "alg"). */
		ck_assert_int_eq(jwt_checker_verify(c, rs), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), rsa_noalg);

		/* Its "kid" naming the oct key binds to a key that can never
		 * verify RS256. */
		ck_assert_int_ne(jwt_checker_verify(c, rs_octkid), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);

		/* No forgery gets an RSA key used as an HMAC secret. */
		for (i = 0; i < ARRAY_SIZE(forged_hs256); i++) {
			ck_assert_int_ne(jwt_checker_verify(c, forged_hs256[i]), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
		}
	}

	jwks_free(rks);
	jwks_free(ring);
}
END_TEST

/* ---- The key's "alg" pin and jwt_checker_setalgs() apply to Compact ---- */
START_TEST(test_compact_keyring_algs)
{
	static const jwt_alg_t only_es256[] = { JWT_ALG_ES256 };
	jwk_set_t *noalg, *pinned, *ring;
	const jwk_item_t *ec, *rsa;
	char_auto *rs512 = NULL, *rs512_kid = NULL, *es = NULL, *rs = NULL;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL;
	size_t i;
	int order;

	SET_OPS();

	/* rsa_key_2048_no_alg.json is rsa_key_2048.json (same "kid") without
	 * the "alg":"RS256", so it can sign RS512. */
	noalg = load_one("rsa_key_2048_no_alg.json");
	rs512 = compact_tok(JWT_ALG_RS512, jwks_item_get(noalg, 0), NULL);
	rs512_kid = compact_tok(JWT_ALG_RS512, jwks_item_get(noalg, 0),
				CKID_RS256);
	ck_assert_ptr_nonnull(rs512);
	ck_assert_ptr_nonnull(rs512_kid);

	/* Pinned to RS256: the same key refuses RS512, scanned or by kid. */
	pinned = ckeys_ring(1u << 1);
	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c1, pinned,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_ne(jwt_checker_verify(c1, rs512), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c1), ERR_POLICY_1);
	ck_assert_int_ne(jwt_checker_verify(c1, rs512_kid), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c1), ERR_POLICY_1);

	/* Control: without the pin the very same tokens verify. */
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c2, noalg,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, rs512), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, rs512_kid), 0);

	/* An algorithm allowlist (set before or after the ring) skips the
	 * signature it does not list, under every policy. */
	ring = ckeys_ring(CKEYS_ALL);
	ec = jwks_find_bykid(ring, CKID_ES256);
	rsa = jwks_find_bykid(ring, CKID_RS256);
	es = compact_tok(JWT_ALG_ES256, ec, CKID_ES256);
	rs = compact_tok(JWT_ALG_RS256, rsa, CKID_RS256);
	ck_assert_ptr_nonnull(es);
	ck_assert_ptr_nonnull(rs);
	for (order = 0; order < 2 * (int)ARRAY_SIZE(both_pol); order++) {
		jwt_checker_auto_t *c = jwt_checker_new();
		jwt_verify_policy_t pol = both_pol[order / 2];

		if (order % 2) {
			ck_assert_int_eq(jwt_checker_setalgs(c, only_es256, 1), 0);
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring, pol), 0);
		} else {
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring, pol), 0);
			ck_assert_int_eq(jwt_checker_setalgs(c, only_es256, 1), 0);
		}

		ck_assert_int_eq(jwt_checker_verify(c, es), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), ec);
		ck_assert_int_ne(jwt_checker_verify(c, rs), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
		for (i = 0; i < ARRAY_SIZE(forged_none); i++) {
			ck_assert_int_ne(jwt_checker_verify(c, forged_none[i]), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_BAD_ALG);
		}
	}

	jwks_free(noalg);
	jwks_free(pinned);
	jwks_free(ring);
}
END_TEST

struct cb_ring_ctx {
	const jwk_item_t *key;	/* key to supply, or NULL to pass through */
	int ret;		/* the callback's return value */
	int calls;
	jwt_alg_t alg_seen;
	const jwk_item_t *key_seen;	/* config->key on entry */
	int sub_seen;		/* the claims carried "sub":"alice" */
};

static int cb_ring(jwt_t *jwt, jwt_config_t *config)
{
	struct cb_ring_ctx *x = config->ctx;
	jwt_value_t v;

	x->calls++;
	x->alg_seen = jwt_get_alg(jwt);
	x->key_seen = config->key;
	jwt_set_GET_STR(&v, "sub");
	x->sub_seen = jwt_claim_get(jwt, &v) == JWT_VALUE_ERR_NONE &&
		      !strcmp(v.str_val, "alice");
	if (x->key != NULL)
		config->key = x->key;

	return x->ret;
}

/* ---- The verify callback runs per signature and may supply the key ---- */
START_TEST(test_compact_keyring_cb)
{
	jwk_set_t *eks, *ring, *octring;
	const jwk_item_t *ec, *ring_ec;
	char_auto *kid = NULL, *scan = NULL, *miss = NULL;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
	struct cb_ring_ctx pass = { 0 }, over = { 0 }, deny = { 0 };

	SET_OPS();

	eks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(eks, 0);
	kid = compact_tok(JWT_ALG_ES256, ec, CKID_ES256);
	scan = compact_tok(JWT_ALG_ES256, ec, NULL);
	miss = compact_tok(JWT_ALG_ES256, ec, "not-in-the-ring");
	ck_assert_ptr_nonnull(kid);
	ck_assert_ptr_nonnull(scan);
	ck_assert_ptr_nonnull(miss);

	/* (a) Pass-through: the callback sees the token's alg and claims and
	 * the kid-selected ring key (none preselected for a kid-less one). */
	ring = ckeys_ring(CKEYS_ALL);
	ring_ec = jwks_find_bykid(ring, CKID_ES256);
	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c1, ring,
		JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_setcb(c1, cb_ring, &pass), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, kid), 0);
	ck_assert_int_eq(pass.calls, 1);
	ck_assert_int_eq(pass.alg_seen, JWT_ALG_ES256);
	ck_assert_ptr_eq(pass.key_seen, ring_ec);
	ck_assert_int_eq(pass.sub_seen, 1);
	ck_assert_ptr_eq(jwt_checker_sig_key(c1, 0), ring_ec);
	ck_assert_int_eq(jwt_checker_verify(c1, scan), 0);
	ck_assert_int_eq(pass.calls, 2);
	ck_assert_ptr_null(pass.key_seen);
	ck_assert_ptr_eq(jwt_checker_sig_key(c1, 0), ring_ec);

	/* (b) Override: the ring lacks the signer, the callback supplies it,
	 * even for a "kid" the ring does not know. */
	octring = ckeys_ring(1u << 0);
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c2, octring,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_ne(jwt_checker_verify(c2, scan), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c2), ERR_POLICY_1);
	over.key = ec;
	ck_assert_int_eq(jwt_checker_setcb(c2, cb_ring, &over), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, scan), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(c2, 0), ec);
	ck_assert_int_eq(jwt_checker_verify(c2, miss), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(c2, 0), ec);
	ck_assert_int_eq(over.calls, 2);

	/* (c) A rejecting callback leaves its signature unverified. */
	deny.ret = 1;
	c3 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c3, ring,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_setcb(c3, cb_ring, &deny), 0);
	ck_assert_int_ne(jwt_checker_verify(c3, kid), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c3), ERR_POLICY_1);
	ck_assert_int_eq(deny.calls, 1);
	ck_assert_int_eq(jwt_checker_sig_verified(c3, 0), 0);

	jwks_free(eks);
	jwks_free(ring);
	jwks_free(octring);
}
END_TEST

/* An @rfc{7797} unencoded payload with '.', quotes and backslashes, shaped to
 * smuggle a "signature" member into JSON text built by string formatting. */
static const unsigned char RAW_TRICKY[] =
	"v1.0 \"q\" \\b\\ \",\"signature\":\"forged.";
#define RAW_TRICKY_LEN (sizeof(RAW_TRICKY) - 1)

/* ---- Unencoded, detached and malformed Compact tokens vs a keyring ---- */
START_TEST(test_compact_keyring_b64)
{
	static const unsigned char claims[] = "{\"sub\":\"alice\"}";
	static const unsigned char binary[] = "\xff.\x01\xc3\x28.z";
	jwk_set_t *ring;
	const jwk_item_t *ec;
	char_auto *tok = NULL, *bad = NULL, *det = NULL, *det64 = NULL;
	char_auto *bin = NULL;
	jwt_checker_auto_t *one = NULL;
	char *p;
	size_t i;

	SET_OPS();
	ring = ckeys_ring(CKEYS_ALL);
	ec = jwks_find_bykid(ring, CKID_ES256);

	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW_TRICKY,
			RAW_TRICKY_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);
	}
	/* The raw payload sits verbatim between the first and last '.'. */
	ck_assert_ptr_nonnull(strstr(tok, (const char *)RAW_TRICKY));

	bad = strdup(tok);
	ck_assert_ptr_nonnull(bad);
	p = strstr(bad, "v1.0");
	ck_assert_ptr_nonnull(p);
	p[1] = '2';	/* v2.0: no longer the signed payload */

	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW_TRICKY,
			RAW_TRICKY_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
		det = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(det);
	}
	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, claims,
			sizeof(claims) - 1), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
		det64 = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(det64);
	}

	for (i = 0; i < ARRAY_SIZE(both_pol); i++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ring, both_pol[i]), 0);

		/* Attached unencoded: verifies (no claims are pinned). */
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), ec);
		ck_assert_int_ne(jwt_checker_verify(c, bad), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);

		/* Detached, unencoded and base64url. */
		ck_assert_int_eq(jwt_checker_verify_detached(c, det,
			RAW_TRICKY, RAW_TRICKY_LEN), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), ec);
		ck_assert_int_ne(jwt_checker_verify_detached(c, det,
			(const unsigned char *)"x.99", 4), 0);
		ck_assert_int_eq(jwt_checker_verify_detached(c, det64,
			claims, sizeof(claims) - 1), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), ec);
		ck_assert_int_ne(jwt_checker_verify_detached(c, det64,
			(const unsigned char *)"{}", 2), 0);

		/* Not a Compact Serialization: no '.', or only one. */
		ck_assert_int_ne(jwt_checker_verify(c, "abc"), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "Invalid JWS Compact Serialization");
		ck_assert_int_ne(jwt_checker_verify(c, NONE_HDR "." EVIL), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "Invalid JWS Compact Serialization");
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
	}

	/* A binary (non-UTF-8, control byte) unencoded payload. The single-key
	 * Compact path takes any bytes. */
	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, binary,
			sizeof(binary) - 1), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		bin = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(bin);
	}
	one = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(one, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_verify(one, bin), 0);
	ck_assert_int_eq(jwt_checker_setkeyring(one, ring,
		JWT_VERIFY_POLICY_ANY), 0);
#ifdef HAVE_JSON_C
	/* json-c carries any bytes in a JSON string, so the keyring verifies
	 * the exact signed bytes. */
	ck_assert_int_eq(jwt_checker_verify(one, bin), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(one, 0), ec);
#else
	/* Jansson cannot hold it in a JSON string: fail closed, with a reason. */
	ck_assert_int_ne(jwt_checker_verify(one, bin), 0);
	ck_assert_str_eq(jwt_checker_error_msg(one), "Token is not valid UTF-8");
#endif

	jwks_free(ring);
}
END_TEST

/* ---- One checker across Compact, JSON, forged and malformed tokens ---- */
START_TEST(test_compact_keyring_reuse)
{
	jwk_set_t *ring;
	const jwk_item_t *ec, *rsa;
	char_auto *es = NULL, *rs = NULL, *general = NULL;
	jwt_checker_auto_t *c = NULL;

	SET_OPS();
	ring = ckeys_ring(CKEYS_ALL);
	ec = jwks_find_bykid(ring, CKID_ES256);
	rsa = jwks_find_bykid(ring, CKID_RS256);
	es = compact_tok(JWT_ALG_ES256, ec, CKID_ES256);
	rs = compact_tok(JWT_ALG_RS256, rsa, NULL);
	ck_assert_ptr_nonnull(es);
	ck_assert_ptr_nonnull(rs);
	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_RS256, rsa), 0);
		ck_assert_ptr_nonnull(jwt_builder_add_signature(b,
			JWT_ALG_ES256, ec));
		general = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(general);
	}

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
		JWT_VERIFY_POLICY_ALL), 0);

	ck_assert_int_eq(jwt_checker_verify(c, es), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), ec);

	ck_assert_int_eq(jwt_checker_verify(c, general), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c), 2);
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), rsa);
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 1), ec);

	ck_assert_int_ne(jwt_checker_verify(c, forged_none[0]), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), ERR_BAD_ALG);
	ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
	ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);

	/* The next error is reported, not the stale one. */
	ck_assert_int_ne(jwt_checker_verify(c, "abc"), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c),
			 "Invalid JWS Compact Serialization");

	ck_assert_int_eq(jwt_checker_verify(c, rs), 0);
	ck_assert_int_eq(jwt_checker_error(c), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), "");
	ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), rsa);

	/* A single key replaces the ring (the last call wins)... */
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_verify(c, es), 0);
	ck_assert_int_ne(jwt_checker_verify(c, rs), 0);
	ck_assert_int_ne(jwt_checker_verify(c, forged_none[0]), 0);

	/* ...and the ring replaces the single key. */
	ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
		JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c, rs), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), rsa);
	ck_assert_int_ne(jwt_checker_verify(c, forged_none[0]), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), ERR_BAD_ALG);

	jwks_free(ring);
}
END_TEST

/* The public half of tests/keys/ec_key_prime256v1.json (no "kid"). */
#define PUB_JWK_P256 \
	"{\"kty\":\"EC\",\"crv\":\"P-256\"," \
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"," \
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}"

/* ---- Embedded-JWK verify keeps precedence over a keyring (Compact) ---- */
START_TEST(test_compact_keyring_embedded)
{
	jwk_set_t *ring;
	const jwk_item_t *ec;
	char_auto *jkt = NULL, *proof = NULL, *plain = NULL;
	int order;

	SET_OPS();
	ring = ckeys_ring(CKEYS_ALL);
	ec = jwks_find_bykid(ring, CKID_ES256);
	jkt = jwks_item_thumbprint(ec, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	{
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_value_t v;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		jwt_set_SET_JSON(&v, "jwk", PUB_JWK_P256);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
		proof = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(proof);
	}
	/* The ring alone would verify this one (its signer is in the ring). */
	plain = compact_tok(JWT_ALG_ES256, ec, CKID_ES256);
	ck_assert_ptr_nonnull(plain);

	for (order = 0; order < 2; order++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		if (order) {
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
				JWT_VERIFY_POLICY_ANY), 0);
			ck_assert_int_eq(jwt_checker_enable_embedded_jwk(c,
				JWK_THUMBPRINT_SHA256, jkt), 0);
		} else {
			ck_assert_int_eq(jwt_checker_enable_embedded_jwk(c,
				JWK_THUMBPRINT_SHA256, jkt), 0);
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
				JWT_VERIFY_POLICY_ANY), 0);
		}

		/* Verified with the confirmed header key, not a ring key. */
		ck_assert_int_eq(jwt_checker_verify(c, proof), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
		ck_assert_ptr_nonnull(jwt_checker_sig_key(c, 0));
		ck_assert_ptr_ne(jwt_checker_sig_key(c, 0), ec);
		ck_assert_ptr_null(jwks_item_kid(jwt_checker_sig_key(c, 0)));

		/* Without a header "jwk" the embedded flow still decides. */
		ck_assert_int_ne(jwt_checker_verify(c, plain), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "Embedded JWK is missing or not confirmed");
		ck_assert_int_ne(jwt_checker_verify(c, forged_none[0]), 0);
	}

	jwks_free(ring);
}
END_TEST

/* ====================================================================
 * The JSON path (which a keyring checker also takes for a Compact token):
 * the pinned algorithm, the type of "kid", and which ring keys it offers.
 * ==================================================================== */

#define ERR_KID_TYPE	"\"kid\" header must be a string"

static const jwt_serialization_t all_fmt[] = {
	JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT, JWT_FORMAT_JSON_GENERAL,
};

/* A token over {"sub":"alice"} signed by @key under @alg in @fmt, with the
 * members of the JSON object @hdr (if not NULL) added to its header. */
static char *fmt_tok(jwt_alg_t alg, const jwk_item_t *key, const char *hdr,
		     jwt_serialization_t fmt)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;
	char *tok;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, alg, key), 0);
	if (hdr != NULL) {
		jwt_set_SET_JSON(&v, NULL, (char *)hdr);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
	}
	jwt_set_SET_STR(&v, "sub", "alice");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(jwt_builder_set_format(b, fmt), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	return tok;
}

struct cb_pin_ctx {
	jwt_alg_t pin;		/* set in config->alg, unless JWT_ALG_NONE */
	jwt_alg_t seen;		/* config->alg as the callback found it */
};

static int cb_pin(jwt_t *jwt, jwt_config_t *config)
{
	struct cb_pin_ctx *x = config->ctx;

	(void)jwt;
	x->seen = config->alg;
	if (x->pin != JWT_ALG_NONE)
		config->alg = x->pin;

	return 0;
}

/* ---- The pinned algorithm holds in every serialization ---- */
START_TEST(test_json_alg_pin)
{
	static const jwt_alg_t other[] = { JWT_ALG_PS256, JWT_ALG_RS512 };
	struct cb_pin_ctx look = { JWT_ALG_NONE, JWT_ALG_NONE };
	struct cb_pin_ctx pin = { JWT_ALG_RS256, JWT_ALG_NONE };
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *one = NULL;
	char_auto *two = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;
	size_t f, i, p;

	SET_OPS();

	/* An RSA key without an "alg" of its own: only the checker, or the
	 * callback, pins one. */
	ks = load_one("rsa_key_2048_no_alg.json");
	key = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(all_fmt); f++) {
		char_auto *rs = fmt_tok(JWT_ALG_RS256, key, NULL, all_fmt[f]);

		for (i = 0; i < ARRAY_SIZE(other); i++) {
			char_auto *t = fmt_tok(other[i], key, NULL, all_fmt[f]);
			struct cb_pin_ctx over = { other[i], JWT_ALG_NONE };
			jwt_checker_auto_t *c1 = NULL, *c2 = NULL;

			/* jwt_checker_setkey(RS256): RS256 verifies, the other
			 * algorithms of the key's type do not, and the callback
			 * sees the pinned one. */
			c1 = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_RS256,
							    key), 0);
			ck_assert_int_eq(jwt_checker_setcb(c1, cb_pin, &look), 0);
			ck_assert_int_eq(jwt_checker_verify(c1, rs), 0);
			look.seen = JWT_ALG_NONE;
			ck_assert_int_ne(jwt_checker_verify(c1, t), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c1),
				all_fmt[f] == JWT_FORMAT_COMPACT ?
				"Config alg does not match JWT" : ERR_POLICY_1);
			ck_assert_int_eq(look.seen, JWT_ALG_RS256);

			/* The callback may pin another algorithm instead. */
			c2 = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_RS256,
							    key), 0);
			ck_assert_int_eq(jwt_checker_setcb(c2, cb_pin, &over), 0);
			ck_assert_int_eq(jwt_checker_verify(c2, t), 0);
			ck_assert_int_ne(jwt_checker_verify(c2, rs), 0);

			/* A keyring pins no algorithm: the callback sees the
			 * signature's own and both tokens verify, unless the
			 * callback pins one. */
			for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
				jwt_checker_auto_t *c = jwt_checker_new();

				ck_assert_int_eq(jwt_checker_setkeyring(c, ks,
					both_pol[p]), 0);
				ck_assert_int_eq(jwt_checker_setcb(c, cb_pin,
					&look), 0);
				ck_assert_int_eq(jwt_checker_verify(c, t), 0);
				ck_assert_int_eq(look.seen, other[i]);
				ck_assert_int_eq(jwt_checker_verify(c, rs), 0);

				ck_assert_int_eq(jwt_checker_setcb(c, cb_pin,
					&pin), 0);
				ck_assert_int_eq(jwt_checker_verify(c, rs), 0);
				ck_assert_int_ne(jwt_checker_verify(c, t), 0);
				ck_assert_str_eq(jwt_checker_error_msg(c),
						 ERR_POLICY_1);
			}
		}
	}

	/* One key signing RS256 and PS256 in a General token: with RS256
	 * pinned, the PS256 signature does not count. */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_RS256, key), 0);
	ck_assert_ptr_nonnull(jwt_builder_add_signature(b, JWT_ALG_PS256, key));
	two = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(two);

	one = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(one, JWT_ALG_RS256, key), 0);
	ck_assert_int_eq(jwt_checker_verify(one, two), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(one), 2);
	ck_assert_int_eq(jwt_checker_sig_verified(one, 0), 1);
	ck_assert_int_eq(jwt_checker_sig_verified(one, 1), 0);

	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ks, both_pol[p]), 0);
		ck_assert_int_eq(jwt_checker_verify(c, two), 0);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 1), 1);

		ck_assert_int_eq(jwt_checker_setcb(c, cb_pin, &pin), 0);
		if (both_pol[p] == JWT_VERIFY_POLICY_ALL) {
			ck_assert_int_ne(jwt_checker_verify(c, two), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c),
				"Signature policy not met (1 of 2 verified)");
		} else {
			ck_assert_int_eq(jwt_checker_verify(c, two), 0);
		}
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 1), 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- A keyring needs any "kid" to be a string ---- */
START_TEST(test_keyring_kid_type)
{
	static const char * const bad[] = {
		"{\"kid\":123}", "{\"kid\":null}", "{\"kid\":[\"x\"]}",
		"{\"kid\":{}}", "{\"kid\":true}",
	};
	char_auto *flat = NULL, *hint = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;
	size_t i, p;

	SET_OPS();

	/* A ring of one key without a "kid": only a scan finds it. */
	ks = load_one("oct_key_256.json");
	key = jwks_item_get(ks, 0);
	flat = fmt_tok(JWT_ALG_HS256, key, NULL, JWT_FORMAT_JSON_FLAT);

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		char_auto *ct = NULL, *ft = NULL, *ut = NULL;
		jwt_checker_auto_t *one = NULL;

		ct = fmt_tok(JWT_ALG_HS256, key, bad[i], JWT_FORMAT_COMPACT);
		ft = fmt_tok(JWT_ALG_HS256, key, bad[i], JWT_FORMAT_JSON_FLAT);
		/* In the unprotected header, which the signature does not
		 * cover. */
		ck_assert_int_gt(asprintf(&ut, "{\"header\":%s,%s", bad[i],
					  flat + 1), 0);

		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_int_eq(jwt_checker_setkeyring(c, ks,
				both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, ct), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KID_TYPE);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
			ck_assert_int_ne(jwt_checker_verify(c, ft), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KID_TYPE);
			ck_assert_int_ne(jwt_checker_verify(c, ut), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KID_TYPE);
		}

		/* A single key is not selected by "kid": no change there. */
		one = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(one, JWT_ALG_HS256, key), 0);
		ck_assert_int_eq(jwt_checker_verify(one, ct), 0);
		ck_assert_int_eq(jwt_checker_verify(one, ft), 0);
	}

	/* A string "kid" in the unprotected header selects no key: the ring
	 * is scanned, as before. */
	ck_assert_int_gt(asprintf(&hint, "{\"header\":{\"kid\":\"hint\"},%s",
				  flat + 1), 0);
	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ks, both_pol[p]), 0);
		ck_assert_int_eq(jwt_checker_verify(c, hint), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), key);
	}

	jwks_free(ks);
}
END_TEST

/* The secret of tests/keys/oct_key_256.json, as ring keys that would each
 * verify its HS256 tokens. Those in not_verify[] are meant for something else,
 * so a keyring does not offer them. */
#define OCT_K "\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}"

static const char * const not_verify[] = {
	"{\"kty\":\"oct\",\"kid\":\"use-enc\",\"use\":\"enc\"," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"use-x\",\"use\":\"x-other\"," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"use-null\",\"use\":null," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"use-num\",\"use\":1," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-wrap\","
		"\"key_ops\":[\"wrapKey\",\"unwrapKey\"]," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-enc\","
		"\"key_ops\":[\"encrypt\",\"decrypt\"]," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-derive\","
		"\"key_ops\":[\"deriveKey\",\"deriveBits\"]," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-empty\",\"key_ops\":[]," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-null\",\"key_ops\":null," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-str\",\"key_ops\":\"verify\"," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"sig-wrap\",\"use\":\"sig\","
		"\"key_ops\":[\"wrapKey\"]," OCT_K,
};

static const char * const for_verify[] = {
	"{\"kty\":\"oct\",\"kid\":\"plain\"," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"use-sig\",\"use\":\"sig\"," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-verify\","
		"\"key_ops\":[\"sign\",\"verify\"]," OCT_K,
	/* As libjwt itself marks a private or HMAC key it exports. */
	"{\"kty\":\"oct\",\"kid\":\"ops-sign\",\"key_ops\":[\"sign\"]," OCT_K,
	"{\"kty\":\"oct\",\"kid\":\"ops-mixed\",\"key_ops\":[1,\"verify\"],"
		OCT_K,
	/* json-c holds a JSON null as NULL: still read the rest. */
	"{\"kty\":\"oct\",\"kid\":\"ops-null-first\","
		"\"key_ops\":[null,\"verify\"]," OCT_K,
};

/* Add the JWKs @jwk[0..@n-1] to @ring, or to a new ring if it is NULL. */
static jwk_set_t *ring_add(jwk_set_t *ring, const char * const *jwk, size_t n)
{
	size_t i;

	if (ring == NULL)
		ring = jwks_create(NULL);
	ck_assert_ptr_nonnull(ring);
	for (i = 0; i < n; i++)
		ck_assert_ptr_nonnull(jwks_load(ring, jwk[i]));
	ck_assert_int_eq(jwks_error_any(ring), 0);

	return ring;
}

/* @tok verifies against @ring under both policies, with its key @k. */
static void ring_verifies_with(const jwk_set_t *ring, const char *tok,
			       const jwk_item_t *k)
{
	size_t p;

	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkeyring(c, ring, both_pol[p]),
				 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), k);
	}
}

/* ---- A keyring offers only keys meant for verification ---- */
START_TEST(test_keyring_key_use)
{
	static const char * const dup[] = {
		"{\"kty\":\"oct\",\"kid\":\"dup\",\"use\":\"enc\"," OCT_K,
		"{\"kty\":\"oct\",\"kid\":\"dup\",\"use\":\"sig\"," OCT_K,
	};
	struct cb_ring_ctx pass = { 0 }, over = { 0 };
	jwk_set_t *ks, *bad, *ring, *dups, *own;
	const jwk_item_t *key, *enc;
	jwt_checker_auto_t *one = NULL, *cb = NULL;
	char_auto *enc_tok = NULL;
	size_t i, f, p;

	SET_OPS();

	ks = load_one("oct_key_256.json");
	key = jwks_item_get(ks, 0);

	/* Only keys meant for something else; then the same, followed by
	 * keys that may verify. */
	bad = ring_add(NULL, not_verify, ARRAY_SIZE(not_verify));
	ring = ring_add(NULL, not_verify, ARRAY_SIZE(not_verify));
	ring_add(ring, for_verify, ARRAY_SIZE(for_verify));
	dups = ring_add(NULL, dup, ARRAY_SIZE(dup));

	for (f = 0; f < 2; f++) {
		jwt_serialization_t fmt = f ? JWT_FORMAT_JSON_FLAT :
					      JWT_FORMAT_COMPACT;
		char_auto *scan = fmt_tok(JWT_ALG_HS256, key, NULL, fmt);
		char_auto *dup_tok = fmt_tok(JWT_ALG_HS256, key,
					     "{\"kid\":\"dup\"}", fmt);

		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			/* The scan skips them all... */
			ck_assert_int_eq(jwt_checker_setkeyring(c, bad,
				both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, scan), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);

			/* ...for the first key that may verify. */
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
				both_pol[p]), 0);
			ck_assert_int_eq(jwt_checker_verify(c, scan), 0);
			ck_assert_str_eq(jwks_item_kid(jwt_checker_sig_key(c, 0)),
					 "plain");

			/* A "kid" naming one of them binds to no key, with no
			 * fallback to the keys that would verify. */
			for (i = 0; i < jwks_item_count(ring); i++) {
				const jwk_item_t *k = jwks_item_get(ring, i);
				char_auto *hdr = NULL, *t = NULL;

				ck_assert_int_gt(asprintf(&hdr, "{\"kid\":\"%s\"}",
						 jwks_item_kid(k)), 0);
				t = fmt_tok(JWT_ALG_HS256, key, hdr, fmt);
				if (i < ARRAY_SIZE(not_verify)) {
					ck_assert_int_ne(jwt_checker_verify(c, t),
							 0);
					ck_assert_str_eq(jwt_checker_error_msg(c),
							 ERR_POLICY_1);
				} else {
					ck_assert_int_eq(jwt_checker_verify(c, t),
							 0);
					ck_assert_ptr_eq(jwt_checker_sig_key(c, 0),
							 k);
				}
			}

			/* Of two keys with that "kid", the one that may verify. */
			ck_assert_int_eq(jwt_checker_setkeyring(c, dups,
				both_pol[p]), 0);
			ck_assert_int_eq(jwt_checker_verify(c, dup_tok), 0);
			ck_assert_ptr_eq(jwt_checker_sig_key(c, 0),
					 jwks_item_get(dups, 1));
		}
	}

	/* The callback is offered no key for a "kid" that names only such a
	 * key, but may supply it, as jwt_checker_setkey() may. */
	enc = jwks_item_get(bad, 0);
	ck_assert_str_eq(jwks_item_kid(enc), "use-enc");
	enc_tok = fmt_tok(JWT_ALG_HS256, key, "{\"kid\":\"use-enc\"}",
			  JWT_FORMAT_COMPACT);
	cb = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(cb, bad,
		JWT_VERIFY_POLICY_ANY), 0);
	pass.key_seen = enc;
	ck_assert_int_eq(jwt_checker_setcb(cb, cb_ring, &pass), 0);
	ck_assert_int_ne(jwt_checker_verify(cb, enc_tok), 0);
	ck_assert_int_eq(pass.calls, 1);
	ck_assert_ptr_null(pass.key_seen);
	over.key = enc;
	ck_assert_int_eq(jwt_checker_setcb(cb, cb_ring, &over), 0);
	ck_assert_int_eq(jwt_checker_verify(cb, enc_tok), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(cb, 0), enc);

	one = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(one, JWT_ALG_HS256, enc), 0);
	ck_assert_int_eq(jwt_checker_verify(one, enc_tok), 0);

	/* The keys libjwt itself imports from an HMAC secret or a private key
	 * carry "key_ops":["sign"]: a keyring offers them, by "kid" and in the
	 * scan. */
	own = jwks_create_fromkey_file(KEYDIR "/pem-files/oct_key_hs256.bin",
				       JWK_KEY_TRY_HMAC | JWK_KEY_GEN_KID);
	ck_assert_ptr_nonnull(own);
	ck_assert_ptr_nonnull(jwks_load_fromkey_file(own,
		KEYDIR "/pem-files/rsa_key_2048.pem", JWK_KEY_GEN_KID));
	ck_assert_int_eq(jwks_error_any(own), 0);
	ck_assert_uint_eq(jwks_item_count(own), 2);
	for (i = 0; i < 2; i++) {
		const jwk_item_t *k = jwks_item_get(own, i);
		jwt_alg_t alg = i ? JWT_ALG_RS256 : JWT_ALG_HS256;
		char_auto *hdr = NULL;

		ck_assert_int_eq(jwks_item_key_ops(k), JWK_KEY_OP_SIGN);
		ck_assert_ptr_nonnull(jwks_item_kid(k));
		ck_assert_int_gt(asprintf(&hdr, "{\"kid\":\"%s\"}",
					  jwks_item_kid(k)), 0);

		for (f = 0; f < 2; f++) {
			jwt_serialization_t fmt = f ? JWT_FORMAT_JSON_FLAT :
						      JWT_FORMAT_COMPACT;
			char_auto *named = fmt_tok(alg, k, hdr, fmt);
			char_auto *scan = fmt_tok(alg, k, NULL, fmt);

			ring_verifies_with(own, named, k);
			ring_verifies_with(own, scan, k);
		}
	}

	jwks_free(ks);
	jwks_free(bad);
	jwks_free(ring);
	jwks_free(dups);
	jwks_free(own);
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
	tcase_add_loop_test(tc_core, test_compact_keyring, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_none, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_confusion, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_algs, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_cb, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_b64, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_reuse, 0, i);
	tcase_add_loop_test(tc_core, test_compact_keyring_embedded, 0, i);
	tcase_add_loop_test(tc_core, test_json_alg_pin, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_kid_type, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_key_use, 0, i);

	tcase_set_timeout(tc_core, 60);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWS JSON Serialization (#308)");
}
