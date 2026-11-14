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

/* The same with a "d" that is not key A's private key (it is A's "x", any 32
 * octets below the group order being one). */
#define MIXED_JWK_P256 \
	"{\"kty\":\"EC\",\"crv\":\"P-256\"," \
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"," \
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"," \
	"\"d\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"}"

#define NOT_CONFIRMED	"Embedded JWK is missing or not confirmed"

static jwk_set_t *load_key_a(void)
{
	jwk_set_t *set = jwks_create_fromfile(KEYDIR "/ec_key_prime256v1.json");

	ck_assert_ptr_nonnull(set);
	return set;
}

/* A self-contained proof: header "jwk" = @jwk_hdr (or none), signed with
 * @signing_key and @alg, typ @typ. Caller frees the token. */
static char *make_proof_alg(jwt_alg_t alg, const jwk_item_t *signing_key,
			    char *jwk_hdr, const char *typ)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, alg, signing_key), 0);
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

/* The same, signed with ES256. */
static char *make_proof(const jwk_item_t *signing_key, char *jwk_hdr,
			const char *typ)
{
	return make_proof_alg(JWT_ALG_ES256, signing_key, jwk_hdr, typ);
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
		/* Key A itself, so the pinned thumbprint matches, but in
		 * error: flagged after it parsed. */
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"x5c\":\"bogus\"}",
		"{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":5,"
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}",
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

/* An unsigned ("alg":"none") token whose header embeds @jwk_hdr: a forgery
 * that needs only the PUBLIC key. @detached leaves @body out of the token.
 * Caller frees it. */
static char *make_unsigned(char *jwk_hdr, const char *body, int detached)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_NONE, NULL), 0);
	jwt_set_SET_JSON(&v, "jwk", jwk_hdr);
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(jwt_builder_setpayload(b, (const unsigned char *)body,
						strlen(body)), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, detached), 0);

	return jwt_builder_generate(b);
}

/* What a verify callback commonly does: pick the key by "kid" (ctx is the
 * set), leaving config->key NULL when the token names none or an unknown one. */
static int kid_lookup_cb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t v;

	jwt_set_GET_STR(&v, "kid");
	config->key = jwt_header_get(jwt, &v) == JWT_VALUE_ERR_NONE ?
		jwks_find_bykid(config->ctx, v.str_val) : NULL;

	return 0;
}

/* GHSA-mhc9-xvg5-qg29: embedded-JWK verify seeds config->alg from the token's
 * own "alg". A callback that left config->key NULL then had the checker treat
 * itself as unkeyed, so a forged unsigned token embedding the pinned public
 * key was accepted, with or without a keyring and through the detached form.
 * The callback may replace the confirmed key, never remove it. */
START_TEST(test_callback_cannot_strip_key)
{
	static const char body[] = "{\"sub\":\"admin\"}";
	const char *nokey = "Callback left no verification key";
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL;
	char_auto *forged = NULL, *forged_det = NULL, *proof = NULL;
	char_auto *proof_kid = NULL;
	int mode;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	forged = make_unsigned(PUB_JWK_P256, body, 0);
	forged_det = make_unsigned(PUB_JWK_P256, body, 1);
	proof = make_proof(key, PUB_JWK_P256, NULL);
	ck_assert_ptr_nonnull(forged);
	ck_assert_ptr_nonnull(forged_det);
	ck_assert_ptr_nonnull(proof);

	/* The same proof naming key A's "kid", which the callback finds. */
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_value_t v;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, key), 0);
		jwt_set_SET_JSON(&v, "jwk", PUB_JWK_P256);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
		jwt_set_SET_STR(&v, "kid", jwks_item_kid(key));
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
		proof_kid = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(proof_kid);
	}

	/* Thumbprint pin, allowlist, and allowlist plus a keyring (which the
	 * embedded-JWK Compact flow takes precedence over). */
	for (mode = 0; mode < 3; mode++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		if (mode == 2)
			ck_assert_int_eq(jwt_checker_setkeyring(c, set,
					JWT_VERIFY_POLICY_ALL), 0);
		if (mode == 0)
			ck_assert_int_eq(jwt_checker_enable_embedded_jwk(c,
					JWK_THUMBPRINT_SHA256, jkt), 0);
		else
			ck_assert_int_eq(jwt_checker_enable_embedded_jwk_keyring(
					c, JWK_THUMBPRINT_SHA256, set), 0);

		/* No callback: the proof verifies, the forgery does not. */
		ck_assert_int_eq(jwt_checker_verify(c, proof), 0);
		ck_assert_int_ne(jwt_checker_verify(c, forged), 0);

		ck_assert_int_eq(jwt_checker_setcb(c, kid_lookup_cb, set), 0);

		ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), nokey);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);

		ck_assert_int_ne(jwt_checker_verify_detached(c, forged_det,
				(const unsigned char *)body, strlen(body)), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), nokey);

		/* A signed proof without a "kid" fails the same way... */
		ck_assert_int_ne(jwt_checker_verify(c, proof), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), nokey);

		/* ...and one whose "kid" the callback finds still verifies. */
		ck_assert_int_eq(jwt_checker_verify(c, proof_kid), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);

		/* A later failure reports only itself: neither an earlier
		 * error nor the last call's signature survives it. */
		ck_assert_int_ne(jwt_checker_verify(c, ""), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), "Must pass a token");
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
	}

	jwks_free(set);
}
END_TEST

/* Verify @token by its header key, confirmed by the pin @jkt or, if that is
 * NULL, by the allow-list @ring. It must verify if @ok and otherwise fail at
 * the confirmation of the header key, before any signature is looked at. */
static void embedded(const char *token, const char *jkt, const jwk_set_t *ring,
		     int ok)
{
	jwt_checker_auto_t *c = jwt_checker_new();
	int ret;

	ck_assert_ptr_nonnull(c);
	if (jkt != NULL)
		ret = jwt_checker_enable_embedded_jwk(c, JWK_THUMBPRINT_SHA256,
						      jkt);
	else
		ret = jwt_checker_enable_embedded_jwk_keyring(c,
					JWK_THUMBPRINT_SHA256, ring);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(c, token);
	if (ok) {
		ck_assert_msg(ret == 0, "%s", jwt_checker_error_msg(c));
		ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	} else {
		ck_assert_int_ne(ret, 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), NOT_CONFIRMED);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
	}
}

/* The header "jwk" is the signer's PUBLIC key (RFC 7515 section 4.1.3). A
 * proof that carries the private key in it is refused, although that key has
 * the pinned thumbprint and did sign the token; so is one whose private member
 * is not even the key's own. Only the public JWK of the same key passes. */
START_TEST(test_private_header_jwk)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL, *priv_jwk = NULL, *pub_jwk = NULL;
	char_auto *t_priv = NULL, *t_mixed = NULL, *t_pub = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	priv_jwk = jwks_item_export(key, 1);
	pub_jwk = jwks_item_export(key, 0);
	ck_assert_ptr_nonnull(priv_jwk);
	ck_assert_ptr_nonnull(pub_jwk);
	ck_assert_ptr_nonnull(strstr(priv_jwk, "\"d\""));
	ck_assert_ptr_null(strstr(pub_jwk, "\"d\""));

	t_priv = make_proof(key, priv_jwk, "dpop+jwt");
	t_mixed = make_proof(key, MIXED_JWK_P256, "dpop+jwt");
	t_pub = make_proof(key, pub_jwk, "dpop+jwt");
	ck_assert_ptr_nonnull(t_priv);
	ck_assert_ptr_nonnull(t_mixed);
	ck_assert_ptr_nonnull(t_pub);

	/* With the thumbprint pin, and with key A on the allow-list. */
	embedded(t_priv, jkt, NULL, 0);
	embedded(t_priv, NULL, set, 0);
	embedded(t_mixed, jkt, NULL, 0);
	embedded(t_mixed, NULL, set, 0);
	embedded(t_pub, jkt, NULL, 1);
	embedded(t_pub, NULL, set, 1);

	jwks_free(set);
}
END_TEST

/* A private member counts whatever its value is, so the refusal does not
 * depend on the backend loading it (the GnuTLS and MbedTLS parsers leave a
 * private member that is not a string aside, and with json-c a JSON null
 * member looks absent to every backend) and is the same in every build. The
 * last header has a member that is private in another key type. */
START_TEST(test_private_member_any_type)
{
	static const char * const hdrs[] = {
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"d\":5}",
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"d\":null}",
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"d\":\"\"}",
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"k\":true}",
	};
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL;
	size_t n;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	for (n = 0; n < ARRAY_SIZE(hdrs); n++) {
		char_auto *token = make_proof(key, (char *)hdrs[n], "dpop+jwt");

		ck_assert_ptr_nonnull(token);
		embedded(token, jkt, NULL, 0);
		embedded(token, NULL, set, 0);
	}

	jwks_free(set);
}
END_TEST

/* A header "jwk" with a "keys" member is a JWK set, not one public key:
 * jwks_create() would read it as a set and confirm only keys[0], parsing the
 * rest on the attacker's say-so. It is refused before any key is loaded,
 * whether the outer object is itself a private key with the public one listed,
 * or a bare set of the pinned public key followed by a private or an "oct"
 * one. The pinned public key alone (no "keys") still passes. */
START_TEST(test_header_jwk_keys_wrapper)
{
	jwk_set_t *set, *oct_set;
	const jwk_item_t *key;
	char_auto *jkt = NULL, *pub_jwk = NULL, *oct_jwk = NULL;
	char_auto *h_priv_keys = NULL, *h_keys_priv = NULL, *h_keys_oct = NULL;
	char_auto *t1 = NULL, *t2 = NULL, *t3 = NULL, *t_ok = NULL;

	SET_OPS();

	set = load_key_a();
	key = jwks_item_get(set, 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);
	pub_jwk = jwks_item_export(key, 0);
	ck_assert_ptr_nonnull(pub_jwk);

	oct_set = jwks_create_fromfile(KEYDIR "/oct_key_256.json");
	ck_assert_ptr_nonnull(oct_set);
	oct_jwk = jwks_item_export(jwks_item_get(oct_set, 0), 1);
	ck_assert_ptr_nonnull(oct_jwk);

	/* Key A's own private JWK, with its public key listed in "keys". */
	ck_assert_int_gt(asprintf(&h_priv_keys,
		"{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"d\":\"wDvSCv8kxkqIVTYPpgEm4Efs6lKzf-95W8Qej4F1yEM\","
		"\"keys\":[%s]}", pub_jwk), 0);
	/* A set: the pinned public key and then a private key, or an "oct". */
	ck_assert_int_gt(asprintf(&h_keys_priv, "{\"keys\":[%s,%s]}",
				  pub_jwk, MIXED_JWK_P256), 0);
	ck_assert_int_gt(asprintf(&h_keys_oct, "{\"keys\":[%s,%s]}",
				  pub_jwk, oct_jwk), 0);

	t1 = make_proof(key, h_priv_keys, "dpop+jwt");
	t2 = make_proof(key, h_keys_priv, "dpop+jwt");
	t3 = make_proof(key, h_keys_oct, "dpop+jwt");
	t_ok = make_proof(key, pub_jwk, "dpop+jwt");
	ck_assert_ptr_nonnull(t1);
	ck_assert_ptr_nonnull(t2);
	ck_assert_ptr_nonnull(t3);
	ck_assert_ptr_nonnull(t_ok);

	/* All three refused -- by pin and by allow-list -- the honest one passes. */
	embedded(t1, jkt, NULL, 0);
	embedded(t1, NULL, set, 0);
	embedded(t2, jkt, NULL, 0);
	embedded(t2, NULL, set, 0);
	embedded(t3, jkt, NULL, 0);
	embedded(t3, NULL, set, 0);
	embedded(t_ok, jkt, NULL, 1);
	embedded(t_ok, NULL, set, 1);

	jwks_free(oct_set);
	jwks_free(set);
}
END_TEST

/* The same for an OKP key, where the key object is made from the private
 * member: a header key with its own, matching "d" is still no public key. */
START_TEST(test_private_header_jwk_okp)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL, *priv_jwk = NULL, *pub_jwk = NULL;
	char_auto *t_priv = NULL, *t_pub = NULL;

	SET_OPS();

	set = jwks_create_fromfile(KEYDIR "/eddsa_key_ed25519.json");
	ck_assert_ptr_nonnull(set);
	key = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(key);
	ck_assert_int_eq(jwks_item_error(key), 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	priv_jwk = jwks_item_export(key, 1);
	pub_jwk = jwks_item_export(key, 0);
	ck_assert_ptr_nonnull(priv_jwk);
	ck_assert_ptr_nonnull(pub_jwk);
	ck_assert_ptr_nonnull(strstr(priv_jwk, "\"d\""));
	ck_assert_ptr_null(strstr(pub_jwk, "\"d\""));

	/* Not every backend has EdDSA to sign the proof with: one without it
	 * loads the key and has nothing to test here. */
	t_pub = make_proof_alg(JWT_ALG_EDDSA, key, pub_jwk, "dpop+jwt");
	if (t_pub == NULL) {
		jwks_free(set);
		return;
	}

	t_priv = make_proof_alg(JWT_ALG_EDDSA, key, priv_jwk, "dpop+jwt");
	ck_assert_ptr_nonnull(t_priv);

	embedded(t_priv, jkt, NULL, 0);
	embedded(t_priv, NULL, set, 0);
	embedded(t_pub, jkt, NULL, 1);
	embedded(t_pub, NULL, set, 1);

	jwks_free(set);
}
END_TEST

/* A symmetric key in the header is the secret itself: whoever reads the token
 * can sign the next one. It has a thumbprint like any key, and is refused. */
START_TEST(test_symmetric_header_jwk)
{
	jwk_set_t *set;
	const jwk_item_t *key;
	char_auto *jkt = NULL, *jwk = NULL, *token = NULL;

	SET_OPS();

	set = jwks_create_fromfile(KEYDIR "/oct_key_256.json");
	ck_assert_ptr_nonnull(set);
	key = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(key);
	ck_assert_int_eq(jwks_item_error(key), 0);
	jkt = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	jwk = jwks_item_export(key, 1);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_ptr_nonnull(strstr(jwk, "\"k\""));

	token = make_proof_alg(JWT_ALG_HS256, key, jwk, "dpop+jwt");
	ck_assert_ptr_nonnull(token);

	embedded(token, jkt, NULL, 0);
	embedded(token, NULL, set, 0);

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
	tcase_add_loop_test(tc_core, test_callback_cannot_strip_key, 0, i);
	tcase_add_loop_test(tc_core, test_private_header_jwk, 0, i);
	tcase_add_loop_test(tc_core, test_private_member_any_type, 0, i);
	tcase_add_loop_test(tc_core, test_header_jwk_keys_wrapper, 0, i);
	tcase_add_loop_test(tc_core, test_private_header_jwk_okp, 0, i);
	tcase_add_loop_test(tc_core, test_symmetric_header_jwk, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT embedded-JWK verify (RFC 7515 4.1.3)");
}
