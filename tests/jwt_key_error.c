/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* A key in error (jwks_item_error()) is never used to sign or to verify,
 * however it reaches the library: set on a builder or a checker, added as a
 * signer, returned by a callback, or held by a keyring (found by "kid" or in
 * the scan). Setting it fails with ERR_KEY; a keyring skips it as if it were
 * absent, and the rest of the keyring keeps working. */

#define ERR_KEY		"Key is in error and cannot be used"
#define ERR_POLICY_1	"Signature policy not met (0 of 1 verified)"
#define ERR_POLICY_2	"Signature policy not met (1 of 2 verified)"

/* The members of tests/keys/ec_key_prime256v1.json ("ES256") and of
 * tests/keys/oct_key_256.json ("HS256"), which sign the tokens below. */
#define EC_PUB	"\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\","	\
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","	\
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\""
#define EC_PRIV	EC_PUB ",\"d\":\"wDvSCv8kxkqIVTYPpgEm4Efs6lKzf-95W8Qej4F1yEM\""

/* The same P-256 public key with NO "alg" of its own: a callback can supply it
 * and the alg has to come from the pin (jwt_checker_setkey()). */
#define EC_PUB_NOALG	"\"kty\":\"EC\",\"crv\":\"P-256\","			\
			"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","	\
			"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\""
#define OCT	"\"kty\":\"oct\",\"alg\":\"HS256\","			\
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\""

/* Flags a key in error AFTER it parsed (an "x5c" that is not an array), on
 * every backend: the key object behind the error works. */
#define FLAG	",\"x5c\":\"bogus\""

/* A key that FAILS to parse, on every backend: the point is not on the curve
 * ("y" is that of tests/keys/ec_key_secp256k1.json). No key object. */
#define EC_OFF	"\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\","	\
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","	\
		"\"y\":\"795Zo2s891l9E7Jb57g9CEvRVGk_LJ7Hy0ixzGcV8UE\""

/* {"alg":"none"} . {"sub":"admin"} . (no signature) */
#define FORGED_NONE	"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."

static const jwt_verify_policy_t both_pol[] = {
	JWT_VERIFY_POLICY_ANY, JWT_VERIFY_POLICY_ALL,
};

static jwk_set_t *load_file(const char *file)
{
	jwk_set_t *set;
	char *path;

	ck_assert_int_gt(asprintf(&path, KEYDIR "/%s", file), 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);

	return set;
}

static jwk_set_t *load_jwk(const char *json)
{
	jwk_set_t *set = jwks_create(json);

	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	ck_assert_ptr_nonnull(jwks_item_get(set, 0));

	return set;
}

/* A token over {"sub":"alice"} signed by @key, with a "kid" header when @kid
 * is not NULL. */
static char *sign_tok(jwt_alg_t alg, const jwk_item_t *key, const char *kid,
		      jwt_serialization_t format)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;
	char *tok;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, alg, key), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, format), 0);
	if (kid != NULL) {
		jwt_set_SET_STR(&v, "kid", kid);
		ck_assert_int_eq(jwt_builder_header_set(b, &v),
				 JWT_VALUE_ERR_NONE);
	}
	jwt_set_SET_STR(&v, "sub", "alice");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);

	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	return tok;
}

/* A callback that records the key it is offered and, if cb_key is set,
 * supplies that one (with cb_alg) instead. */
static const jwk_item_t *cb_key, *cb_seen;
static jwt_alg_t cb_alg;
static int cb_calls;

static int key_cb(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;

	cb_calls++;
	cb_seen = config->key;
	if (cb_key != NULL) {
		config->key = cb_key;
		config->alg = cb_alg;
	}

	return 0;
}

/* Supplies the key but leaves config->alg alone, as a key-selection callback
 * that only looks up a key does. */
static int key_only_cb(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;

	cb_calls++;
	cb_seen = config->key;
	if (cb_key != NULL)
		config->key = cb_key;

	return 0;
}

/* Does every one of the @sigs signatures of @tok verify against @ring? */
static void verifies_all(const char *tok, const jwk_set_t *ring,
			 unsigned int sigs)
{
	jwt_checker_auto_t *c = jwt_checker_new();

	ck_assert_ptr_nonnull(c);
	ck_assert_ptr_nonnull(tok);
	ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
						JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c), sigs);
}

/* ---- jwt_checker_setkey(), jwt_builder_setkey(), _add_signature() ---- */
START_TEST(test_setkey_errored)
{
	static const struct {
		const char *jwk;
		jwt_alg_t alg;
	} bad[] = {
		{ "{" EC_PUB FLAG "}",  JWT_ALG_ES256 },	/* flagged	*/
		{ "{" EC_PRIV FLAG "}", JWT_ALG_ES256 },
		{ "{" OCT FLAG "}",     JWT_ALG_HS256 },
		{ "{" EC_OFF "}",       JWT_ALG_ES256 },	/* no key object */
		{ "{\"kty\":\"oct\",\"alg\":\"HS256\"}", JWT_ALG_HS256 },
		/* An "alg" that is not a string, and an unknown "kty". */
		{ "{\"alg\":5,\"kty\":\"EC\",\"crv\":\"P-256\","
		  "\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		  "\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}",
		  JWT_ALG_ES256 },
		{ "{\"kty\":\"XYZ\",\"alg\":\"ES256\"}", JWT_ALG_ES256 },
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		jwk_set_t *set = load_jwk(bad[i].jwk);
		const jwk_item_t *key = jwks_item_get(set, 0);

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_nonnull(c);
		ck_assert_int_ne(jwks_item_error(key), 0);

		/* With the key's own "alg", and with the one given. */
		ck_assert_int_ne(jwt_checker_setkey(c, JWT_ALG_NONE, key), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KEY);
		jwt_checker_error_clear(c);
		ck_assert_int_ne(jwt_checker_setkey(c, bad[i].alg, key), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KEY);

		/* The same error for a public key as for a private one. */
		ck_assert_int_ne(jwt_builder_setkey(b, bad[i].alg, key), 0);
		ck_assert_str_eq(jwt_builder_error_msg(b), ERR_KEY);
		jwt_builder_error_clear(b);
		ck_assert_ptr_null(jwt_builder_add_signature(b, bad[i].alg,
							     key));
		ck_assert_str_eq(jwt_builder_error_msg(b), ERR_KEY);

		jwks_free(set);
	}
}
END_TEST

/* A checker that was given only a key in error is not left unkeyed, where it
 * would accept an unsigned token for an application that ignores the failed
 * jwt_checker_setkey(). */
START_TEST(test_setkey_errored_fails_closed)
{
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL, *c4 = NULL;
	jwt_checker_auto_t *c5 = NULL;
	char_auto *tok = NULL, *jtok = NULL;
	jwk_set_t *good_set, *bad_set;
	const jwk_item_t *good, *bad;

	SET_OPS();

	good_set = load_file("ec_key_prime256v1.json");
	good = jwks_item_get(good_set, 0);
	bad_set = load_jwk("{" EC_PUB FLAG "}");
	bad = jwks_item_get(bad_set, 0);

	tok = sign_tok(JWT_ALG_ES256, good, NULL, JWT_FORMAT_COMPACT);
	jtok = sign_tok(JWT_ALG_ES256, good, NULL, JWT_FORMAT_JSON_FLAT);

	/* It verifies nothing, signed or not, ... */
	c1 = jwt_checker_new();
	ck_assert_ptr_nonnull(c1);
	ck_assert_int_ne(jwt_checker_setkey(c1, JWT_ALG_ES256, bad), 0);
	ck_assert_int_ne(jwt_checker_verify(c1, FORGED_NONE), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c1), ERR_KEY);
	ck_assert_int_ne(jwt_checker_verify(c1, tok), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c1), ERR_KEY);
	ck_assert_int_ne(jwt_checker_verify(c1, jtok), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c1), "No key or keyring set");

	/* ... until it is given a key that works, */
	ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_ES256, good), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, tok), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, jtok), 0);
	ck_assert_int_ne(jwt_checker_verify(c1, FORGED_NONE), 0);

	/* or the application itself makes it unkeyed. The latch is then gone: an
	 * unsigned token is turned away by the unsigned-token default (issue
	 * #352), not ERR_KEY, and the JWT_ALG_NONE opt-in accepts it. */
	c2 = jwt_checker_new();
	ck_assert_ptr_nonnull(c2);
	ck_assert_int_ne(jwt_checker_setkey(c2, JWT_ALG_ES256, bad), 0);
	ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_NONE, NULL), 0);
	ck_assert_int_ne(jwt_checker_verify(c2, FORGED_NONE), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c2),
			 "Unsigned tokens are not allowed");
	checker_allow_none(c2);
	ck_assert_int_eq(jwt_checker_verify(c2, FORGED_NONE), 0);

	/* A refused key does not replace the one the checker has. */
	c3 = jwt_checker_new();
	ck_assert_ptr_nonnull(c3);
	ck_assert_int_eq(jwt_checker_setkey(c3, JWT_ALG_ES256, good), 0);
	ck_assert_int_ne(jwt_checker_setkey(c3, JWT_ALG_ES256, bad), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c3), ERR_KEY);
	ck_assert_int_eq(jwt_checker_verify(c3, tok), 0);
	ck_assert_ptr_eq(jwt_checker_sig_key(c3, 0), good);
	ck_assert_int_ne(jwt_checker_verify(c3, FORGED_NONE), 0);

	/* A verify callback can still supply the key; when it does not, the
	 * checker has none, and says so as for any callback. */
	c4 = jwt_checker_new();
	ck_assert_ptr_nonnull(c4);
	ck_assert_int_ne(jwt_checker_setkey(c4, JWT_ALG_ES256, bad), 0);
	ck_assert_int_eq(jwt_checker_setcb(c4, key_cb, NULL), 0);
	cb_key = good;
	cb_alg = JWT_ALG_ES256;
	ck_assert_int_eq(jwt_checker_verify(c4, tok), 0);
	cb_key = NULL;
	ck_assert_int_ne(jwt_checker_verify(c4, tok), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c4),
			 "Callback left no verification key");
	ck_assert_int_ne(jwt_checker_verify(c4, FORGED_NONE), 0);

	/* A keyring settles it as a key does. */
	c5 = jwt_checker_new();
	ck_assert_ptr_nonnull(c5);
	ck_assert_int_ne(jwt_checker_setkey(c5, JWT_ALG_ES256, bad), 0);
	ck_assert_int_eq(jwt_checker_setkeyring(c5, good_set,
						JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c5, tok), 0);
	ck_assert_int_eq(jwt_checker_verify(c5, jtok), 0);
	ck_assert_int_ne(jwt_checker_verify(c5, FORGED_NONE), 0);

	jwks_free(bad_set);
	jwks_free(good_set);
}
END_TEST

/* Nor does a builder that was given only a key in error produce an unsigned
 * token for an application that ignores the failed jwt_builder_setkey(). */
START_TEST(test_setkey_errored_builder_fails_closed)
{
	jwt_builder_auto_t *b1 = NULL, *b2 = NULL, *b3 = NULL;
	jwk_set_t *good_set, *bad_set;
	const jwk_item_t *good, *bad;
	char_auto *t1 = NULL, *t2 = NULL, *t3 = NULL;

	SET_OPS();

	good_set = load_file("ec_key_prime256v1.json");
	good = jwks_item_get(good_set, 0);
	bad_set = load_jwk("{" EC_PRIV FLAG "}");
	bad = jwks_item_get(bad_set, 0);

	/* It generates nothing ... */
	b1 = jwt_builder_new();
	ck_assert_ptr_nonnull(b1);
	ck_assert_int_ne(jwt_builder_setkey(b1, JWT_ALG_ES256, bad), 0);
	jwt_builder_error_clear(b1);
	ck_assert_ptr_null(jwt_builder_generate(b1));
	ck_assert_str_eq(jwt_builder_error_msg(b1), ERR_KEY);

	/* ... until it is given a key that works, */
	jwt_builder_error_clear(b1);
	ck_assert_int_eq(jwt_builder_setkey(b1, JWT_ALG_ES256, good), 0);
	t1 = jwt_builder_generate(b1);
	ck_assert_ptr_nonnull(t1);
	ck_assert_int_eq(jwt_builder_error(b1), 0);

	/* or the application asks for an unsigned token itself. */
	b2 = jwt_builder_new();
	ck_assert_ptr_nonnull(b2);
	ck_assert_int_ne(jwt_builder_setkey(b2, JWT_ALG_ES256, bad), 0);
	jwt_builder_error_clear(b2);
	ck_assert_int_eq(jwt_builder_setkey(b2, JWT_ALG_NONE, NULL), 0);
	t2 = jwt_builder_generate(b2);
	ck_assert_ptr_nonnull(t2);

	/* A refused key does not replace the one the builder has. */
	b3 = jwt_builder_new();
	ck_assert_ptr_nonnull(b3);
	ck_assert_int_eq(jwt_builder_setkey(b3, JWT_ALG_ES256, good), 0);
	ck_assert_int_ne(jwt_builder_setkey(b3, JWT_ALG_ES256, bad), 0);
	jwt_builder_error_clear(b3);
	t3 = jwt_builder_generate(b3);
	ck_assert_ptr_nonnull(t3);
	ck_assert_ptr_nonnull(strstr(t3, "eyJhbGciOiJFUzI1NiIs"));

	jwks_free(bad_set);
	jwks_free(good_set);
}
END_TEST

/* A refusal withholds an unsigned token and nothing else: the builder signs
 * with every key it is given afterwards, however it is given, in every
 * serialization (a JSON serialization is never unsigned). */
START_TEST(test_setkey_errored_then_signers)
{
	static const jwt_serialization_t fmt[] = {
		JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT,
		JWT_FORMAT_JSON_GENERAL,
	};
	jwk_set_t *ec_set, *oct_set, *bad_set, *ring;
	const jwk_item_t *ec, *oct, *bad;
	size_t f;

	SET_OPS();

	ec_set = load_file("ec_key_prime256v1.json");
	ec = jwks_item_get(ec_set, 0);
	oct_set = load_file("oct_key_256.json");
	oct = jwks_item_get(oct_set, 0);
	bad_set = load_jwk("{" EC_PRIV FLAG "}");
	bad = jwks_item_get(bad_set, 0);
	ring = load_jwk("{\"keys\":[{" EC_PUB "},{" OCT "}]}");

	/* A jwt_builder_setkey() that succeeds, ... */
	for (f = 0; f < ARRAY_SIZE(fmt); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, bad), 0);
		jwt_builder_error_clear(b);
		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, fmt[f]), 0);
		tok = jwt_builder_generate(b);
		verifies_all(tok, ring, 1);
	}

	/* ... with a second signer, */
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, bad), 0);
		jwt_builder_error_clear(b);
		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_ptr_nonnull(jwt_builder_add_signature(b,
						JWT_ALG_HS256, oct));
		tok = jwt_builder_generate(b);
		verifies_all(tok, ring, 2);
	}

	/* a callback that supplies the key, */
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, bad), 0);
		jwt_builder_error_clear(b);
		cb_key = ec;
		cb_alg = JWT_ALG_ES256;
		ck_assert_int_eq(jwt_builder_setcb(b, key_cb, NULL), 0);
		tok = jwt_builder_generate(b);
		verifies_all(tok, ring, 1);
	}

	/* or signers added with jwt_builder_add_signature(). */
	for (f = 1; f < ARRAY_SIZE(fmt); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, bad), 0);
		jwt_builder_error_clear(b);
		ck_assert_ptr_nonnull(jwt_builder_add_signature(b,
						JWT_ALG_ES256, ec));
		if (fmt[f] == JWT_FORMAT_JSON_GENERAL)
			ck_assert_ptr_nonnull(jwt_builder_add_signature(b,
						JWT_ALG_HS256, oct));
		else
			ck_assert_int_eq(jwt_builder_set_format(b, fmt[f]), 0);
		tok = jwt_builder_generate(b);
		verifies_all(tok, ring, fmt[f] == JWT_FORMAT_JSON_GENERAL ?
			     2 : 1);
	}

	/* The key a builder has keeps signing when a signer is refused. */
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_ptr_null(jwt_builder_add_signature(b, JWT_ALG_ES256,
							     bad));
		jwt_builder_error_clear(b);
		tok = jwt_builder_generate(b);
		verifies_all(tok, ring, 1);
	}

	jwks_free(ring);
	jwks_free(bad_set);
	jwks_free(oct_set);
	jwks_free(ec_set);
}
END_TEST

/* jwt_builder_add_signature() refusing a key in error leaves no unsigned
 * token behind either: with no signer left, nothing is generated. */
START_TEST(test_addsig_errored_fails_closed)
{
	jwt_builder_auto_t *b1 = NULL, *b2 = NULL, *b3 = NULL, *b4 = NULL;
	jwt_builder_auto_t *b5 = NULL;
	jwk_set_t *ec_set, *oct_set, *bad_set, *bad2_set, *ring;
	const jwk_item_t *ec, *oct, *bad, *bad2;
	char_auto *t3 = NULL, *t4 = NULL;

	SET_OPS();

	ec_set = load_file("ec_key_prime256v1.json");
	ec = jwks_item_get(ec_set, 0);
	oct_set = load_file("oct_key_256.json");
	oct = jwks_item_get(oct_set, 0);
	bad_set = load_jwk("{" EC_PRIV FLAG "}");
	bad = jwks_item_get(bad_set, 0);
	bad2_set = load_jwk("{" OCT FLAG "}");
	bad2 = jwks_item_get(bad2_set, 0);
	ring = load_jwk("{\"keys\":[{" EC_PUB "},{" OCT "}]}");

	/* The only signer is refused: no Compact token (it would be unsigned)
	 * and, as before, no JSON one without a signer. */
	b1 = jwt_builder_new();
	ck_assert_ptr_nonnull(b1);
	ck_assert_ptr_null(jwt_builder_add_signature(b1, JWT_ALG_ES256, bad));
	ck_assert_str_eq(jwt_builder_error_msg(b1), ERR_KEY);
	jwt_builder_error_clear(b1);
	ck_assert_ptr_null(jwt_builder_generate(b1));
	ck_assert_str_eq(jwt_builder_error_msg(b1), ERR_KEY);
	jwt_builder_error_clear(b1);
	ck_assert_int_eq(jwt_builder_set_format(b1, JWT_FORMAT_JSON_FLAT), 0);
	ck_assert_ptr_null(jwt_builder_generate(b1));
	ck_assert_str_eq(jwt_builder_error_msg(b1),
			 "No key set for JSON serialization");

	/* Two signers, both refused: nothing in place of the two signatures. */
	b2 = jwt_builder_new();
	ck_assert_ptr_nonnull(b2);
	ck_assert_ptr_null(jwt_builder_add_signature(b2, JWT_ALG_ES256, bad));
	ck_assert_ptr_null(jwt_builder_add_signature(b2, JWT_ALG_HS256, bad2));
	jwt_builder_error_clear(b2);
	ck_assert_ptr_null(jwt_builder_generate(b2));
	ck_assert_str_eq(jwt_builder_error_msg(b2), ERR_KEY);

	/* An application that skips the signer it was refused goes on with the
	 * others. */
	b3 = jwt_builder_new();
	ck_assert_ptr_nonnull(b3);
	ck_assert_ptr_null(jwt_builder_add_signature(b3, JWT_ALG_ES256, bad));
	jwt_builder_error_clear(b3);
	ck_assert_ptr_nonnull(jwt_builder_add_signature(b3, JWT_ALG_ES256, ec));
	ck_assert_ptr_nonnull(jwt_builder_add_signature(b3, JWT_ALG_HS256,
							oct));
	t3 = jwt_builder_generate(b3);
	verifies_all(t3, ring, 2);

	/* An unsigned token is still there for the asking, ... */
	b4 = jwt_builder_new();
	ck_assert_ptr_nonnull(b4);
	ck_assert_ptr_null(jwt_builder_add_signature(b4, JWT_ALG_ES256, bad));
	jwt_builder_error_clear(b4);
	ck_assert_int_eq(jwt_builder_setkey(b4, JWT_ALG_NONE, NULL), 0);
	t4 = jwt_builder_generate(b4);
	ck_assert_ptr_nonnull(t4);
	ck_assert_int_eq(t4[strlen(t4) - 1], '.');

	/* ... until a key is asked for again and refused. */
	b5 = jwt_builder_new();
	ck_assert_ptr_nonnull(b5);
	ck_assert_int_eq(jwt_builder_setkey(b5, JWT_ALG_NONE, NULL), 0);
	ck_assert_int_ne(jwt_builder_setkey(b5, JWT_ALG_ES256, bad), 0);
	jwt_builder_error_clear(b5);
	ck_assert_ptr_null(jwt_builder_generate(b5));
	ck_assert_str_eq(jwt_builder_error_msg(b5), ERR_KEY);

	jwks_free(ring);
	jwks_free(bad2_set);
	jwks_free(bad_set);
	jwks_free(oct_set);
	jwks_free(ec_set);
}
END_TEST

/* After a key in error is refused, a callback that supplies a replacement key
 * but not the alg still signs/verifies with the alg that was asked for, as it
 * did before the key was refused (GHSA-4jp4-6w6j-ff4q regression): a builder
 * takes the replacement key's own "alg"; a checker keeps the pinned alg, so
 * even a bare public key with no "alg" of its own verifies. Without this the
 * builder emitted an "alg":"none" token and the checker failed every token. */
START_TEST(test_errored_cb_alg_less)
{
	jwk_set_t *signer_set, *bad_set, *pub_set, *ring;
	const jwk_item_t *signer, *bad, *pub;
	char_auto *tok = NULL;

	SET_OPS();

	signer_set = load_file("ec_key_prime256v1.json");	/* "alg":"ES256" */
	signer = jwks_item_get(signer_set, 0);
	bad_set = load_jwk("{" EC_PRIV FLAG "}");
	bad = jwks_item_get(bad_set, 0);
	pub_set = load_jwk("{" EC_PUB_NOALG "}");		/* no "alg" */
	pub = jwks_item_get(pub_set, 0);
	ring = load_jwk("{" EC_PUB "}");
	tok = sign_tok(JWT_ALG_ES256, signer, NULL, JWT_FORMAT_COMPACT);

	/* Builder: the callback supplies the private key, not the alg. */
	cb_key = signer;
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *out = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, bad), 0);
		jwt_builder_error_clear(b);
		ck_assert_int_eq(jwt_builder_setcb(b, key_only_cb, NULL), 0);
		out = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(out);
		/* Signed ES256, not "alg":"none". */
		ck_assert_ptr_nonnull(strstr(out, "eyJhbGciOiJFUzI1NiIs"));
		verifies_all(out, ring, 1);
	}

	/* The same after a refused jwt_builder_add_signature(). */
	{
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *out = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_null(jwt_builder_add_signature(b, JWT_ALG_ES256,
							     bad));
		jwt_builder_error_clear(b);
		ck_assert_int_eq(jwt_builder_setcb(b, key_only_cb, NULL), 0);
		out = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(out);
		ck_assert_ptr_nonnull(strstr(out, "eyJhbGciOiJFUzI1NiIs"));
		verifies_all(out, ring, 1);
	}

	/* Checker: the callback supplies a bare public key with no "alg"; the
	 * ES256 asked for at the refused setkey is what verifies the token. */
	cb_key = pub;
	{
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ck_assert_int_ne(jwt_checker_setkey(c, JWT_ALG_ES256, bad), 0);
		ck_assert_int_eq(jwt_checker_setcb(c, key_only_cb, NULL), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
		ck_assert_int_ne(jwt_checker_verify(c, FORGED_NONE), 0);
	}

	cb_key = NULL;
	jwks_free(ring);
	jwks_free(pub_set);
	jwks_free(bad_set);
	jwks_free(signer_set);
}
END_TEST

/* The key_required latch is only for a key in error. A setkey/add_signature
 * refused for another reason (a public key for signing, an alg/kty mismatch)
 * does not latch: the object is left exactly as unkeyed as it was. */
START_TEST(test_latch_boundary)
{
	jwk_set_t *pub_set, *oct_set;
	const jwk_item_t *pub, *oct;
	char_auto *tok = NULL;

	SET_OPS();

	pub_set = load_jwk("{" EC_PUB "}");	/* a public key, not in error */
	pub = jwks_item_get(pub_set, 0);
	oct_set = load_file("oct_key_256.json");
	oct = jwks_item_get(oct_set, 0);

	/* Builder: signing needs a private key, so a public one is refused, but
	 * not for being in error, so there is no latch: with no key the builder
	 * still makes the unsigned token it would make unkeyed. */
	{
		jwt_builder_auto_t *b = jwt_builder_new();

		ck_assert_ptr_nonnull(b);
		ck_assert_int_ne(jwt_builder_setkey(b, JWT_ALG_ES256, pub), 0);
		ck_assert_str_eq(jwt_builder_error_msg(b),
				 "Signing requires a private key");
		jwt_builder_error_clear(b);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);
		ck_assert_int_eq(tok[strlen(tok) - 1], '.');
	}

	/* Checker: an alg/kty mismatch is refused, again not for being in error,
	 * so the checker is simply left unkeyed (not the key_required
	 * fail-closed): a latched checker would reject even an unsigned token
	 * with ERR_KEY, where an unkeyed one takes it (with the JWT_ALG_NONE
	 * opt-in, issue #352), as it would with no setkey at all. */
	{
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ck_assert_int_ne(jwt_checker_setkey(c, JWT_ALG_ES256, oct), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "Key type does not match algorithm");
		jwt_checker_error_clear(c);
		checker_allow_none(c);
		ck_assert_int_eq(jwt_checker_verify(c, FORGED_NONE), 0);
	}

	jwks_free(oct_set);
	jwks_free(pub_set);
}
END_TEST

/* A JSON null member is treated as absent, the same under both JSON backends:
 * "x5c":null and "alg":null must not put the key in error (Jansson used to
 * flag them, json-c read them as absent -- a divergence that an in-error key
 * never being used would turn into one backend refusing what the other uses).
 * The key loads clean and verifies on both. */
START_TEST(test_json_null_members)
{
	static const char * const variants[] = {
		"{" EC_PUB_NOALG ",\"x5c\":null}",
		"{" EC_PUB_NOALG ",\"alg\":null}",
		"{" EC_PUB_NOALG ",\"alg\":null,\"x5c\":null}",
	};
	jwk_set_t *signer_set;
	const jwk_item_t *signer;
	char_auto *tok = NULL;
	size_t n;

	SET_OPS();

	signer_set = load_file("ec_key_prime256v1.json");
	signer = jwks_item_get(signer_set, 0);
	tok = sign_tok(JWT_ALG_ES256, signer, NULL, JWT_FORMAT_COMPACT);

	for (n = 0; n < ARRAY_SIZE(variants); n++) {
		jwk_set_t *set = jwks_create(variants[n]);
		const jwk_item_t *key;
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);
		key = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(key);
		/* The same error state on both backends: not in error. */
		ck_assert_int_eq(jwks_item_error(key), 0);

		/* And the same verify result: the key is usable. */
		ck_assert_ptr_nonnull(c);
		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, key), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

		jwks_free(set);
	}

	jwks_free(signer_set);
}
END_TEST

/* ---- A key in error returned by a callback ---- */
static const struct {
	const char *signer;	/* signs the token			*/
	const char *pub;	/* that key flagged in error (verify)	*/
	const char *priv;	/* that key flagged in error (sign)	*/
	jwt_alg_t alg;
} flagged[] = {
	/* jwt_verify_sig() -> __check_key_bits() */
	{ "ec_key_prime256v1.json", "{" EC_PUB FLAG "}", "{" EC_PRIV FLAG "}",
	  JWT_ALG_ES256 },
	/* jwt_verify_sig() -> jwt_sign() -> __check_hmac() */
	{ "oct_key_256.json", "{" OCT FLAG "}", "{" OCT FLAG "}",
	  JWT_ALG_HS256 },
};

/* Compact token, no key on the checker: the callback's key is refused as
 * jwt_checker_setkey() would refuse it. Likewise for a builder. */
START_TEST(test_callback_errored)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(flagged); i++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		jwk_set_t *sset = load_file(flagged[i].signer);
		jwk_set_t *vset = load_jwk(flagged[i].pub);
		jwk_set_t *pset = load_jwk(flagged[i].priv);
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_nonnull(c);
		tok = sign_tok(flagged[i].alg, jwks_item_get(sset, 0), NULL,
			       JWT_FORMAT_COMPACT);

		cb_alg = flagged[i].alg;
		cb_key = jwks_item_get(vset, 0);
		ck_assert_int_ne(jwks_item_error(cb_key), 0);
		ck_assert_int_eq(jwt_checker_setcb(c, key_cb, NULL), 0);
		ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KEY);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);

		/* The key it is flagged for would have verified. */
		cb_key = jwks_item_get(sset, 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

		cb_key = jwks_item_get(pset, 0);
		ck_assert_int_ne(jwks_item_error(cb_key), 0);
		ck_assert_int_eq(jwt_builder_setcb(b, key_cb, NULL), 0);
		ck_assert_ptr_null(jwt_builder_generate(b));
		ck_assert_str_eq(jwt_builder_error_msg(b), ERR_KEY);

		jwks_free(pset);
		jwks_free(vset);
		jwks_free(sset);
	}
}
END_TEST

/* A JWS JSON Serialization, and a Compact token checked against a keyring
 * (verified as one): the callback's key is the only one tried, and one in
 * error leaves that signature unverified for the policy to decide. */
START_TEST(test_callback_errored_json)
{
	static const jwt_serialization_t fmt[] = {
		JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT,
	};
	size_t i, f;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(flagged); i++) {
		jwk_set_t *sset = load_file(flagged[i].signer);
		jwk_set_t *vset = load_jwk(flagged[i].pub);
		const jwk_item_t *signer = jwks_item_get(sset, 0);

		for (f = 0; f < ARRAY_SIZE(fmt); f++) {
			jwt_checker_auto_t *c = jwt_checker_new();
			char_auto *tok = sign_tok(flagged[i].alg, signer, NULL,
						  fmt[f]);

			ck_assert_ptr_nonnull(c);
			/* The ring alone verifies the token. */
			ck_assert_int_eq(jwt_checker_setkeyring(c, sset,
				JWT_VERIFY_POLICY_ANY), 0);
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

			cb_alg = flagged[i].alg;
			cb_key = jwks_item_get(vset, 0);
			ck_assert_int_eq(jwt_checker_setcb(c, key_cb, NULL), 0);
			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
			ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
			ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 0);
			ck_assert_ptr_null(jwt_checker_sig_key(c, 0));
		}

		/* The same with the signer's key set on the checker, in place
		 * of a keyring that holds it. */
		{
			jwt_checker_auto_t *c = jwt_checker_new();
			char_auto *tok = sign_tok(flagged[i].alg, signer, NULL,
						  JWT_FORMAT_JSON_FLAT);

			ck_assert_ptr_nonnull(c);
			cb_key = NULL;
			ck_assert_int_eq(jwt_checker_setkey(c, flagged[i].alg,
							    signer), 0);
			ck_assert_int_eq(jwt_checker_setcb(c, key_cb, NULL), 0);
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

			cb_alg = flagged[i].alg;
			cb_key = jwks_item_get(vset, 0);
			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
			ck_assert_ptr_null(jwt_checker_sig_key(c, 0));
		}

		jwks_free(vset);
		jwks_free(sset);
	}
}
END_TEST

/* ---- Keyrings ---- */

/* The scan (a token without a "kid") skips the keys in error and goes on to
 * the others; jwt_checker_setkeyring() accepts a ring that holds some. */
START_TEST(test_keyring_errored_scan)
{
	jwk_set_t *sset, *only, *mixed, *all_bad, *x5t;
	const jwk_item_t *signer;
	size_t f, p;

	SET_OPS();

	sset = load_file("ec_key_prime256v1.json");
	signer = jwks_item_get(sset, 0);

	/* Only the signer's own key, flagged in error. */
	only = load_jwk("{" EC_PUB FLAG "}");
	/* A key that failed to parse, that flagged key, then the key itself. */
	mixed = load_jwk("{\"keys\":[{" EC_OFF "},{" EC_PUB FLAG "},{" EC_PUB "}]}");
	ck_assert_int_eq(jwks_error_any(mixed), 2);
	ck_assert_int_eq(jwks_item_error(jwks_item_get(mixed, 2)), 0);
	/* Nothing but keys in error, of every type. */
	all_bad = load_file("bad_keys.json");
	ck_assert_int_eq(jwks_error_any(all_bad), (int)jwks_item_count(all_bad));
	/* A key whose "x5t#S256" is not that of its "x5c" leaf certificate. */
	x5t = load_file("ec_key_x5c_bad_x5t.json");
	ck_assert_int_ne(jwks_item_error(jwks_item_get(x5t, 0)), 0);

	for (f = 0; f < 2; f++) {
		char_auto *tok = sign_tok(JWT_ALG_ES256, signer, NULL,
			f ? JWT_FORMAT_JSON_FLAT : JWT_FORMAT_COMPACT);

		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_ptr_nonnull(c);

			ck_assert_int_eq(jwt_checker_setkeyring(c, only,
							both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
			ck_assert_ptr_null(jwt_checker_sig_key(c, 0));

			ck_assert_int_eq(jwt_checker_setkeyring(c, all_bad,
							both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);

			ck_assert_int_eq(jwt_checker_setkeyring(c, x5t,
							both_pol[p]), 0);
			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);

			ck_assert_int_eq(jwt_checker_setkeyring(c, mixed,
							both_pol[p]), 0);
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
			ck_assert_ptr_eq(jwt_checker_sig_key(c, 0),
					 jwks_item_get(mixed, 2));
		}
	}

	/* Still a keyring checker: never an unsigned token. */
	{
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ck_assert_int_eq(jwt_checker_setkeyring(c, all_bad,
					JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_ne(jwt_checker_verify(c, FORGED_NONE), 0);
	}

	jwks_free(x5t);
	jwks_free(all_bad);
	jwks_free(mixed);
	jwks_free(only);
	jwks_free(sset);
}
END_TEST

/* A "kid" never names a key in error: the next key with that "kid" is used,
 * and if there is none the signature does not verify (no scan). The verify
 * callback is not offered the key either. */
START_TEST(test_keyring_errored_kid)
{
	static const char * const dups[] = {
		"{\"keys\":[{\"kid\":\"k1\"," EC_PUB FLAG "},"
			   "{\"kid\":\"k1\"," EC_PUB "}]}",
		"{\"keys\":[{\"kid\":\"k1\"," EC_OFF "},"
			   "{\"kid\":\"k1\"," EC_PUB "}]}",
	};
	jwk_set_t *sset, *only;
	const jwk_item_t *signer;
	char_auto *tok = NULL;
	size_t i, p;

	SET_OPS();

	sset = load_file("ec_key_prime256v1.json");
	signer = jwks_item_get(sset, 0);
	tok = sign_tok(JWT_ALG_ES256, signer, "k1", JWT_FORMAT_COMPACT);

	cb_key = NULL;	/* key_cb() only records what it is offered */

	for (i = 0; i < ARRAY_SIZE(dups); i++) {
		jwk_set_t *ring = load_jwk(dups[i]);

		ck_assert_int_ne(jwks_item_error(jwks_item_get(ring, 0)), 0);
		ck_assert_int_eq(jwks_item_error(jwks_item_get(ring, 1)), 0);
		/* The public finder still returns the first match as it is. */
		ck_assert_ptr_eq(jwks_find_bykid(ring, "k1"),
				 jwks_item_get(ring, 0));

		for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_ptr_nonnull(c);
			ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
							both_pol[p]), 0);
			ck_assert_int_eq(jwt_checker_setcb(c, key_cb, NULL), 0);
			cb_seen = NULL;
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
			ck_assert_ptr_eq(cb_seen, jwks_item_get(ring, 1));
			ck_assert_ptr_eq(jwt_checker_sig_key(c, 0),
					 jwks_item_get(ring, 1));
		}

		jwks_free(ring);
	}

	/* The only key with that "kid" is in error; another key of the ring
	 * would verify the signature, but a "kid" does not fall back. */
	only = load_jwk("{\"keys\":[{\"kid\":\"k1\"," EC_PUB FLAG "},"
				   "{\"kid\":\"k2\"," EC_PUB "}]}");
	for (p = 0; p < ARRAY_SIZE(both_pol); p++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ck_assert_int_eq(jwt_checker_setkeyring(c, only, both_pol[p]), 0);
		ck_assert_int_eq(jwt_checker_setcb(c, key_cb, NULL), 0);
		cb_seen = signer;
		cb_calls = 0;
		ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), ERR_POLICY_1);
		ck_assert_int_eq(cb_calls, 1);
		ck_assert_ptr_null(cb_seen);
		ck_assert_ptr_null(jwt_checker_sig_key(c, 0));
	}

	jwks_free(only);
	jwks_free(sset);
}
END_TEST

/* Two signatures, the key of one in error: that signature does not verify, so
 * ANY accepts the token on the other and ALL rejects it. */
START_TEST(test_keyring_errored_policy)
{
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c_any = NULL, *c_all = NULL;
	jwk_set_t *ec_set, *oct_set, *ring;
	jwt_signature_t *s;
	char_auto *tok = NULL;

	SET_OPS();

	ec_set = load_file("ec_key_prime256v1.json");
	oct_set = load_file("oct_key_256.json");
	ring = load_jwk("{\"keys\":[{\"kid\":\"ec\"," EC_PUB "},"
				   "{\"kid\":\"oct\"," OCT FLAG "}]}");

	b = jwt_builder_new();
	ck_assert_ptr_nonnull(b);
	s = jwt_builder_add_signature(b, JWT_ALG_ES256, jwks_item_get(ec_set, 0));
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(jwt_signature_add_protected_json(s, "kid", "\"ec\""), 0);
	s = jwt_builder_add_signature(b, JWT_ALG_HS256, jwks_item_get(oct_set, 0));
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(jwt_signature_add_protected_json(s, "kid", "\"oct\""), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	c_any = jwt_checker_new();
	ck_assert_ptr_nonnull(c_any);
	ck_assert_int_eq(jwt_checker_setkeyring(c_any, ring,
				JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c_any, tok), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c_any), 2);
	ck_assert_int_eq(jwt_checker_sig_verified(c_any, 0), 1);
	ck_assert_int_eq(jwt_checker_sig_verified(c_any, 1), 0);
	ck_assert_ptr_null(jwt_checker_sig_key(c_any, 1));

	c_all = jwt_checker_new();
	ck_assert_ptr_nonnull(c_all);
	ck_assert_int_eq(jwt_checker_setkeyring(c_all, ring,
				JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_ne(jwt_checker_verify(c_all, tok), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c_all), ERR_POLICY_2);

	jwks_free(ring);
	jwks_free(oct_set);
	jwks_free(ec_set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_key_error");

	tcase_add_loop_test(tc_core, test_setkey_errored, 0, i);
	tcase_add_loop_test(tc_core, test_setkey_errored_fails_closed, 0, i);
	tcase_add_loop_test(tc_core, test_setkey_errored_builder_fails_closed, 0, i);
	tcase_add_loop_test(tc_core, test_setkey_errored_then_signers, 0, i);
	tcase_add_loop_test(tc_core, test_addsig_errored_fails_closed, 0, i);
	tcase_add_loop_test(tc_core, test_errored_cb_alg_less, 0, i);
	tcase_add_loop_test(tc_core, test_latch_boundary, 0, i);
	tcase_add_loop_test(tc_core, test_json_null_members, 0, i);
	tcase_add_loop_test(tc_core, test_callback_errored, 0, i);
	tcase_add_loop_test(tc_core, test_callback_errored_json, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_errored_scan, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_errored_kid, 0, i);
	tcase_add_loop_test(tc_core, test_keyring_errored_policy, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT keys in error are never used");
}
