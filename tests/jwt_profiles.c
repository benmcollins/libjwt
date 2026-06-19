/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Worked, end-to-end recipes for the real-world JWT application profiles of
 * issue #317. Each builds AND verifies a token using only the public primitives
 * (no per-profile API): at+jwt (RFC 9068), VAPID (RFC 8292), PASSporT
 * (RFC 8225), OpenID4VCI key-proof, DPoP (RFC 9449), OAuth mTLS (RFC 8705), and
 * JAdES (ETSI 119 182-1). One EC P-256 key (ES256, every backend) is used. */

/* The public half of tests/keys/ec_key_prime256v1.json. */
#define PUB_JWK_P256 \
	"{\"kty\":\"EC\",\"crv\":\"P-256\"," \
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"," \
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}"

static jwk_set_t *load_key(void)
{
	jwk_set_t *set = jwks_create_fromfile(KEYDIR "/ec_key_prime256v1.json");

	ck_assert_ptr_nonnull(set);
	return set;
}

static void set_str(jwt_builder_t *b, const char *name, const char *val)
{
	jwt_value_t v;

	jwt_set_SET_STR(&v, name, val);
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
}

/* ---- RFC 9068 OAuth 2.0 JWT access token (typ "at+jwt") ---------------- */
START_TEST(test_at_jwt)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *token = NULL;
	const char *required[] = { "iss", "sub", "aud", "exp", "iat",
				   "jti", "client_id" };
	const jwt_alg_t algs[] = { JWT_ALG_ES256 };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);

	/* Issue: typ=at+jwt and the RFC 9068 mandatory claims. */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_settyp(b, "at+jwt"), 0);
	set_str(b, "iss", "https://as.example");
	set_str(b, "sub", "user-1");
	set_str(b, "aud", "https://rs.example");
	set_str(b, "client_id", "client-42");
	set_str(b, "jti", "wU3ifM");
	ck_assert_int_eq(jwt_builder_time_offset(b, JWT_CLAIM_EXP, 300), 0);
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	/* Verify: pin typ + alg, and assert the mandatory claims are present. */
	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_expect_typ(c, "at+jwt"), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);
	ck_assert_int_eq(jwt_checker_require(c, required, ARRAY_SIZE(required)), 0);
	ck_assert_int_eq(jwt_checker_claim_set(c, JWT_CLAIM_AUD, "https://rs.example"), 0);
	ck_assert_int_eq(jwt_checker_verify(c, token), 0);

	jwks_free(set);
}
END_TEST

/* ---- RFC 8292 VAPID (Web Push) ---------------------------------------- */
START_TEST(test_vapid)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *token = NULL;
	const char *required[] = { "aud", "exp", "sub" };
	const jwt_alg_t algs[] = { JWT_ALG_ES256 };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);

	/* A plain ES256 JWS over P-256: aud=push origin, sub=contact, short exp. */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	set_str(b, "aud", "https://push.example.com");
	set_str(b, "sub", "mailto:admin@example.com");
	ck_assert_int_eq(jwt_builder_time_offset(b, JWT_CLAIM_EXP, 12 * 3600), 0);
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);	/* ES256 only */
	ck_assert_int_eq(jwt_checker_require(c, required, ARRAY_SIZE(required)), 0);
	ck_assert_int_eq(jwt_checker_verify(c, token), 0);

	jwks_free(set);
}
END_TEST

/* ---- RFC 8225 PASSporT / STIR-SHAKEN (typ "passport") ------------------ */
START_TEST(test_passport)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *token = NULL;
	const char *required[] = { "iat", "orig", "dest" };
	const jwt_alg_t algs[] = { JWT_ALG_ES256 };
	jwt_value_t v;

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);

	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_settyp(b, "passport"), 0);
	set_str(b, "attest", "A");
	/* orig/dest are JSON objects per RFC 8225. */
	jwt_set_SET_JSON(&v, "orig", "{\"tn\":\"12155551212\"}");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	jwt_set_SET_JSON(&v, "dest", "{\"tn\":[\"12155551213\"]}");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_expect_typ(c, "passport"), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);
	ck_assert_int_eq(jwt_checker_require(c, required, ARRAY_SIZE(required)), 0);
	ck_assert_int_eq(jwt_checker_verify(c, token), 0);

	jwks_free(set);
}
END_TEST

/* ---- OpenID4VCI key proof (typ "openid4vci-proof+jwt") ----------------- */
START_TEST(test_openid4vci_proof)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *jkt = NULL;
	char_auto *token = NULL;
	jwt_value_t v;
	const jwt_alg_t algs[] = { JWT_ALG_ES256 };

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	/* The proof's signing key IS the header "jwk"; the credential request
	 * binds the credential to that key (its thumbprint here). */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_settyp(b, "openid4vci-proof+jwt"), 0);
	jwt_set_SET_JSON(&v, "jwk", PUB_JWK_P256);
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	set_str(b, "iss", "client-42");
	set_str(b, "aud", "https://issuer.example");
	set_str(b, "nonce", "c_nonce_from_issuer");
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_expect_typ(c, "openid4vci-proof+jwt"), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(c,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_eq(jwt_checker_verify(c, token), 0);

	jwks_free(set);
}
END_TEST

/* ---- RFC 9449 DPoP (typ "dpop+jwt") ----------------------------------- */
struct dpop_ctx {
	const char *access_token;
	int ok;
};

static int dpop_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct dpop_ctx *d = config->ctx;
	jwt_value_t v;
	char *ath;
	const char *htm, *got_ath;

	jwt_set_GET_STR(&v, "htm");
	if (jwt_claim_get(jwt, &v) != JWT_VALUE_ERR_NONE)
		return 1;
	htm = v.str_val;

	jwt_set_GET_STR(&v, "ath");
	if (jwt_claim_get(jwt, &v) != JWT_VALUE_ERR_NONE)
		return 1;
	got_ath = v.str_val;

	/* ath = base64url(SHA-256(access_token)). */
	ath = jwt_token_hash(d->access_token, JWK_THUMBPRINT_SHA256);
	d->ok = (ath != NULL && !strcmp(ath, got_ath) && !strcmp(htm, "POST"));
	free(ath);

	return 0;
}

START_TEST(test_dpop)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *atb = NULL, *pb = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *jkt = NULL;
	char_auto *access_token = NULL;
	char_auto *ath = NULL;
	char_auto *proof = NULL;
	jwt_value_t v;
	struct dpop_ctx d;

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	/* The AS issues an access token bound to the holder key via cnf.jkt. */
	atb = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(atb, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_setcnf_jkt(atb, key), 0);
	set_str(atb, "sub", "user-1");
	access_token = jwt_builder_generate(atb);
	ck_assert_ptr_nonnull(access_token);

	ath = jwt_token_hash(access_token, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(ath);

	/* The client makes a DPoP proof carrying its key in the header. */
	pb = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(pb, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_settyp(pb, "dpop+jwt"), 0);
	jwt_set_SET_JSON(&v, "jwk", PUB_JWK_P256);
	ck_assert_int_eq(jwt_builder_header_set(pb, &v), JWT_VALUE_ERR_NONE);
	set_str(pb, "htm", "POST");
	set_str(pb, "htu", "https://rs.example/resource");
	set_str(pb, "jti", "Xy123");
	set_str(pb, "ath", ath);
	proof = jwt_builder_generate(pb);
	ck_assert_ptr_nonnull(proof);

	/* The RS confirms the proof's self-key against the AT's cnf.jkt and that
	 * its ath binds to the presented access token. */
	memset(&d, 0, sizeof(d));
	d.access_token = access_token;

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_expect_typ(c, "dpop+jwt"), 0);
	{
		const jwt_alg_t algs[] = { JWT_ALG_ES256 };
		ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);
	}
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(c,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_eq(jwt_checker_setcb(c, dpop_cb, &d), 0);
	ck_assert_int_eq(jwt_checker_verify(c, proof), 0);
	ck_assert_int_eq(d.ok, 1);

	jwks_free(set);
}
END_TEST

/* ---- RFC 8705 OAuth 2.0 mutual-TLS certificate-bound token ------------- */
struct mtls_ctx {
	const char *presented_x5t;	/* SHA-256 thumbprint of the client cert */
	int ok;
};

static int mtls_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct mtls_ctx *m = config->ctx;
	char *bound = jwt_get_cnf(jwt, "x5t#S256");

	/* The token is accepted only if its cnf.x5t#S256 equals the thumbprint
	 * of the certificate presented in the TLS handshake (computed by the
	 * caller / TLS terminator). */
	m->ok = (bound != NULL && !strcmp(bound, m->presented_x5t));
	free(bound);

	return 0;
}

START_TEST(test_mtls)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *token = NULL;
	struct mtls_ctx m;
	const char *cert_thumb = "bwcK0esc3ACC3DB2Y5_lESsXE8u9ie-9UWlCEx4dyk8";

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);

	/* The AS binds the access token to the client certificate. */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_settyp(b, "at+jwt"), 0);
	ck_assert_int_eq(jwt_builder_setcnf(b, "x5t#S256", cert_thumb), 0);
	set_str(b, "iss", "https://as.example");
	set_str(b, "sub", "user-1");
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	memset(&m, 0, sizeof(m));
	m.presented_x5t = cert_thumb;

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_expect_typ(c, "at+jwt"), 0);
	ck_assert_int_eq(jwt_checker_setcb(c, mtls_cb, &m), 0);
	ck_assert_int_eq(jwt_checker_verify(c, token), 0);
	ck_assert_int_eq(m.ok, 1);

	jwks_free(set);
}
END_TEST

/* ---- ETSI 119 182-1 JAdES: detached payload + x5c cert chain ----------- */
struct jades_ctx {
	int has_x5c;
};

static int jades_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct jades_ctx *j = config->ctx;
	jwt_value_t v;

	/* The signing certificate chain rides in the protected "x5c" header. */
	jwt_set_GET_JSON(&v, "x5c");
	if (jwt_header_get(jwt, &v) == JWT_VALUE_ERR_NONE) {
		j->has_x5c = (v.json_val != NULL &&
			      strstr(v.json_val, "MII") != NULL);
		free(v.json_val);
	}

	return 0;
}

START_TEST(test_jades)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *token = NULL;
	jwt_value_t v;
	struct jades_ctx j;
	const unsigned char payload[] = "JAdES signs this detached document";

	SET_OPS();

	set = load_key();
	key = jwks_item_get(set, 0);

	/* Sign a detached payload; carry the cert chain in x5c. */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_builder_setpayload(b, payload,
				sizeof(payload) - 1), 0);
	/* The document is opaque, not JSON claims: sign it unencoded (RFC 7797). */
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
	jwt_set_SET_JSON(&v, "x5c", "[\"MIIBdummyLeafCertBase64==\"]");
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	token = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(token);

	memset(&j, 0, sizeof(j));

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
	ck_assert_int_eq(jwt_checker_setcb(c, jades_cb, &j), 0);
	/* The detached payload is supplied out of band. */
	ck_assert_int_eq(jwt_checker_verify_detached(c, token, payload,
				sizeof(payload) - 1), 0);
	ck_assert_int_eq(j.has_x5c, 1);

	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_profiles");

	tcase_add_loop_test(tc_core, test_at_jwt, 0, i);
	tcase_add_loop_test(tc_core, test_vapid, 0, i);
	tcase_add_loop_test(tc_core, test_passport, 0, i);
	tcase_add_loop_test(tc_core, test_openid4vci_proof, 0, i);
	tcase_add_loop_test(tc_core, test_dpop, 0, i);
	tcase_add_loop_test(tc_core, test_mtls, 0, i);
	tcase_add_loop_test(tc_core, test_jades, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT application profiles (#317)");
}
