/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for embedded-JWK verification (RFC 7515 4.1.3): jwt_checker_enable_
 * embedded_jwk() (thumbprint pin) and _keyring() (allowlist). The header "jwk"
 * is attacker-supplied, so the security contract is that it is accepted ONLY
 * after the key is confirmed against a caller-supplied pin/allowlist AND its
 * signature verifies against that confirmed key. This is the DPoP / OpenID4VCI
 * key-proof mechanism. The proof carries the P-256 public key in its protected
 * header and is signed by the matching private key. */

/* The public half of tests/keys/ec_key_prime256v1.json (key "A"). */
#define PUB_JWK_P256 \
	"{\"kty\":\"EC\",\"crv\":\"P-256\"," \
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"," \
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}"

static jwk_set_t *load_key_a(void)
{
	jwk_set_t *set = jwks_create_fromfile(KEYDIR "/ec_key_prime256v1.json");

	ck_assert_ptr_nonnull(set);
	return set;
}

/* A self-contained proof: header "jwk" = @jwk_hdr (or none), signed with
 * @signing_key, typ @typ. Caller frees the token. */
static char *make_proof(const jwk_item_t *signing_key, char *jwk_hdr,
			const char *typ)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, signing_key), 0);
	if (typ != NULL)
		ck_assert_int_eq(jwt_builder_settyp(b, typ), 0);
	if (jwk_hdr != NULL) {
		jwt_set_SET_JSON(&v, "jwk", jwk_hdr);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
	}
	jwt_set_SET_STR(&v, "htm", "POST");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);

	return jwt_builder_generate(b);
}

START_TEST(test_pin_confirms)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *jkt = NULL;
	char_auto *token = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	token = make_proof(key, PUB_JWK_P256, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_expect_typ(checker, "dpop+jwt"), 0);
	{
		const jwt_alg_t algs[] = { JWT_ALG_ES256 };
		ck_assert_int_eq(jwt_checker_setalgs(checker, algs, 1), 0);
	}
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, jkt), 0);

	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	/* The confirmed embedded key is borrowable through the introspection API. */
	ck_assert_uint_eq(jwt_checker_sig_count(checker), 1);
	ck_assert_int_eq(jwt_checker_sig_verified(checker, 0), 1);
	ck_assert_ptr_nonnull(jwt_checker_sig_key(checker, 0));

	jwks_free(set);
}
END_TEST

START_TEST(test_pin_mismatch_rejected)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	token = make_proof(key, PUB_JWK_P256, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	/* Pin to a thumbprint the embedded key does not match. */
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256,
				"not-the-right-thumbprint-value-000000000000"), 0);
	ck_assert_int_ne(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

START_TEST(test_missing_header_jwk_rejected)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *jkt = NULL;
	char_auto *token = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	/* A token with no "jwk" header at all. */
	token = make_proof(key, NULL, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_ne(jwt_checker_verify(checker, token), 0);

	jwks_free(set);
}
END_TEST

/* The crux: even when the embedded key's thumbprint matches the pin, the
 * signature must verify against THAT key. A proof that embeds key A's public
 * key but is signed by a different key B must be rejected. */
START_TEST(test_signature_must_match_embedded)
{
	jwk_set_t *set, *bset;
	const jwk_item_t *akey, *bkey;
	jwt_checker_auto_t *checker = NULL;
	char_auto *jkt = NULL;
	char_auto *token = NULL;

	SET_OPS();

	set = load_key_a();
	akey = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(akey, JWK_THUMBPRINT_SHA256);

	bset = jwks_create_generate(JWK_KEY_TYPE_EC, "P-256", JWT_ALG_ES256,
				    JWK_KEY_NONE);
	ck_assert_ptr_nonnull(bset);
	bkey = jwks_item_get(bset, 0);
	if (bkey == NULL || jwks_item_error(bkey)) {
		/* A backend with no EC keygen: nothing to test here. */
		jwks_free(bset);
		jwks_free(set);
		return;
	}

	/* header jwk = A (matches the pin), but signed by B. */
	token = make_proof(bkey, PUB_JWK_P256, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_ne(jwt_checker_verify(checker, token), 0);

	jwks_free(bset);
	jwks_free(set);
}
END_TEST

START_TEST(test_keyring_allowlist)
{
	jwk_set_t *set, *other;
	const jwk_item_t *key;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL;
	char_auto *token = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	token = make_proof(key, PUB_JWK_P256, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	/* The allowlist contains key A: accepted. */
	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk_keyring(c1,
				JWK_THUMBPRINT_SHA256, set), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, token), 0);

	/* An allowlist of some other key: rejected. */
	other = jwks_create_fromfile(KEYDIR "/ec_key_secp256k1.json");
	ck_assert_ptr_nonnull(other);
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk_keyring(c2,
				JWK_THUMBPRINT_SHA256, other), 0);
	ck_assert_int_ne(jwt_checker_verify(c2, token), 0);

	jwks_free(other);
	jwks_free(set);
}
END_TEST

/* A malformed/incomplete header "jwk" is rejected, not crashed on (the header
 * key is fully attacker-controlled). */
START_TEST(test_malformed_embedded_jwk)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL;
	const char *bad[] = {
		"{\"kty\":\"EC\",\"crv\":\"P-256\"}",	/* missing x/y */
		"{\"kty\":\"frobnicate\"}",		/* unknown kty */
		"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"@\",\"y\":\"@\"}",
		"{}",					/* empty object */
	};
	size_t n;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	for (n = 0; n < ARRAY_SIZE(bad); n++) {
		jwt_checker_auto_t *cc = jwt_checker_new();
		char *t = make_proof(key, (char *)bad[n], "dpop+jwt");

		ck_assert_ptr_nonnull(t);
		ck_assert_int_eq(jwt_checker_enable_embedded_jwk(cc,
					JWK_THUMBPRINT_SHA256, jkt), 0);
		/* A malformed header key is rejected, never crashed on. */
		ck_assert_int_ne(jwt_checker_verify(cc, t), 0);
		free(t);
	}

	jwks_free(set);
}
END_TEST

/* One embedded-JWK checker verifies two proofs in a row: the confirmed key from
 * the first verify must be released before the second borrows its own. */
START_TEST(test_checker_reuse)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *jkt = NULL;
	char_auto *t1 = NULL, *t2 = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	t1 = make_proof(key, PUB_JWK_P256, "dpop+jwt");
	t2 = make_proof(key, PUB_JWK_P256, "dpop+jwt");
	ck_assert_ptr_nonnull(t1);
	ck_assert_ptr_nonnull(t2);

	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, t1), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, t2), 0);

	jwks_free(set);
}
END_TEST

START_TEST(test_enable_errors)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	jwt_checker_auto_t *checker = NULL;
	char_auto *jkt = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);

	checker = jwt_checker_new();

	/* No "trust whatever is embedded" mode: a NULL/empty pin must fail. */
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk(NULL,
				JWK_THUMBPRINT_SHA256, jkt), 0);
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, NULL), 0);
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk(checker,
				JWK_THUMBPRINT_SHA256, ""), 0);
	/* An out-of-range thumbprint selector. */
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk(checker,
				(jwk_thumbprint_alg_t)42, jkt), 0);
	/* The keyring form: NULL checker, bad alg, and a missing keyring all fail. */
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk_keyring(NULL,
				JWK_THUMBPRINT_SHA256, set), 0);
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk_keyring(checker,
				(jwk_thumbprint_alg_t)42, set), 0);
	ck_assert_int_ne(jwt_checker_enable_embedded_jwk_keyring(checker,
				JWK_THUMBPRINT_SHA256, NULL), 0);

	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_embedded_jwk");

	tcase_add_loop_test(tc_core, test_pin_confirms, 0, i);
	tcase_add_loop_test(tc_core, test_pin_mismatch_rejected, 0, i);
	tcase_add_loop_test(tc_core, test_missing_header_jwk_rejected, 0, i);
	tcase_add_loop_test(tc_core, test_signature_must_match_embedded, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_allowlist, 0, i);
	tcase_add_loop_test(tc_core, test_malformed_embedded_jwk, 0, i);
	tcase_add_loop_test(tc_core, test_checker_reuse, 0, i);
	tcase_add_loop_test(tc_core, test_enable_errors, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT embedded-JWK verify (RFC 7515 4.1.3)");
}
