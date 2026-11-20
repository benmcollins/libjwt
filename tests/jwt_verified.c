/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* jwt_checker_verified_jwt() and jwt_checker_sig_header_get() (#362): after a
 * verify that returns 0 the checker hands back the token it accepted (claims,
 * and for a Compact or Flattened token the protected header and verified alg)
 * and each verified signature's protected header, until its next verify or
 * jwt_checker_free(). Nothing is readable after a failure or from a callback.
 * Every test runs under each compiled crypto backend (SET_OPS()), and the
 * suite is built under both JSON backends. */

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
	ck_assert_int_eq(jwks_error(set), 0);

	return set;
}

static void set_str(jwt_builder_t *b, int header, const char *name,
		    const char *val)
{
	jwt_value_t v;

	jwt_set_SET_STR(&v, name, val);
	ck_assert_int_eq(header ? jwt_builder_header_set(b, &v) :
			 jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
}

static void set_int(jwt_builder_t *b, const char *name, jwt_long_t val)
{
	jwt_value_t v;

	jwt_set_SET_INT(&v, name, val);
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
}

/* The claims and shared header every test token carries: a string, an integer
 * and a boolean claim, and an application header member; and a "jti" and an
 * "exp" if @jti is not NULL or @exp not 0. */
static void std_claims(jwt_builder_t *b, const char *sub, const char *jti,
		       jwt_long_t exp)
{
	jwt_value_t v;

	if (jti != NULL)
		set_str(b, 0, "jti", jti);
	if (exp != 0)
		set_int(b, "exp", exp);
	set_str(b, 0, "sub", sub);
	set_str(b, 0, "scope", "read");
	set_int(b, "n", 42);
	jwt_set_SET_BOOL(&v, "flag", 1);
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	set_str(b, 1, "x-tenant", "acme");
}

/* A token signed with @key under @alg in @fmt, with std_claims(). */
static char *make_tok(jwt_alg_t alg, const jwk_item_t *key,
		      jwt_serialization_t fmt, const char *sub,
		      const char *jti, jwt_long_t exp)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	char *tok;

	ck_assert_ptr_nonnull(b);
	std_claims(b, sub, jti, exp);
	ck_assert_int_eq(jwt_builder_setkey(b, alg, key), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, fmt), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	return tok;
}

/* A General token signed with ES256 (@ec) then RS256 (@rsa), each signature
 * with its own protected "x-signer" and an unprotected "x-unprot". */
static char *make_general(const jwk_item_t *ec, const jwk_item_t *rsa,
			  const char *sub, const char *jti, jwt_long_t exp)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_signature_t *s;
	char *tok;

	ck_assert_ptr_nonnull(b);
	std_claims(b, sub, jti, exp);
	s = jwt_builder_add_signature(b, JWT_ALG_ES256, ec);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(jwt_signature_add_protected_json(s, "x-signer",
							  "\"ec\""), 0);
	ck_assert_int_eq(jwt_signature_add_header_json(s, "x-unprot",
						       "\"u0\""), 0);
	s = jwt_builder_add_signature(b, JWT_ALG_RS256, rsa);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(jwt_signature_add_protected_json(s, "x-signer",
							  "\"rsa\""), 0);
	ck_assert_int_eq(jwt_signature_add_header_json(s, "x-unprot",
						       "\"u1\""), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);
	ck_assert_int_eq(tok[0], '{');

	return tok;
}

/* Nothing is readable from @c: no token and no signature header. */
static void check_nothing(jwt_checker_t *c)
{
	jwt_value_t v;
	unsigned int i;

	ck_assert_ptr_null(jwt_checker_verified_jwt(c));
	for (i = 0; i < 3; i++) {
		jwt_set_GET_STR(&v, "alg");
		ck_assert_int_eq(jwt_checker_sig_header_get(c, i, &v),
				 JWT_VALUE_ERR_INVALID);
		ck_assert_int_eq(v.error, JWT_VALUE_ERR_INVALID);
	}
}

/* @c's accepted token carries std_claims(@sub). */
static void check_claims(jwt_checker_t *c, const char *sub)
{
	jwt_t *jwt = jwt_checker_verified_jwt(c);
	jwt_value_t v;

	ck_assert_ptr_nonnull(jwt);

	jwt_set_GET_STR(&v, "sub");
	ck_assert_int_eq(jwt_claim_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, sub);

	jwt_set_GET_INT(&v, "n");
	ck_assert_int_eq(jwt_claim_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(v.int_val, 42);

	jwt_set_GET_BOOL(&v, "flag");
	ck_assert_int_eq(jwt_claim_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(v.bool_val, 1);

	jwt_set_GET_JSON(&v, NULL);
	ck_assert_int_eq(jwt_claim_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_ptr_nonnull(v.json_val);
	ck_assert_ptr_nonnull(strstr(v.json_val, "\"scope\":\"read\""));
	ck_assert_ptr_nonnull(strstr(v.json_val, "\"n\":42"));
	free(v.json_val);
}

/* Signature @idx of @c's accepted token verified under @alg and carries the
 * shared "x-tenant" header (and "x-signer" @signer if not NULL), and never
 * its unprotected "x-unprot". */
static void check_sig_header(jwt_checker_t *c, unsigned int idx, jwt_alg_t alg,
			     const char *signer)
{
	jwt_value_t v;

	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, idx, &v),
			 JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, jwt_alg_str(alg));

	jwt_set_GET_STR(&v, "x-tenant");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, idx, &v),
			 JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, "acme");

	if (signer != NULL) {
		jwt_set_GET_STR(&v, "x-signer");
		ck_assert_int_eq(jwt_checker_sig_header_get(c, idx, &v),
				 JWT_VALUE_ERR_NONE);
		ck_assert_str_eq(v.str_val, signer);
	}

	jwt_set_GET_STR(&v, "x-unprot");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, idx, &v),
			 JWT_VALUE_ERR_NOEXIST);
	ck_assert_int_eq(v.error, JWT_VALUE_ERR_NOEXIST);

	jwt_set_GET_JSON(&v, NULL);
	ck_assert_int_eq(jwt_checker_sig_header_get(c, idx, &v),
			 JWT_VALUE_ERR_NONE);
	ck_assert_ptr_nonnull(strstr(v.json_val, "\"x-tenant\":\"acme\""));
	ck_assert_ptr_null(strstr(v.json_val, "x-unprot"));
	free(v.json_val);
}

/* A Compact or Flattened token: the jwt_t holds the protected header and the
 * verified alg, and signature 0 reads the same header. */
static void check_single(jwt_checker_t *c, jwt_alg_t alg, const char *sub)
{
	jwt_t *jwt;
	jwt_value_t v;

	check_claims(c, sub);
	jwt = jwt_checker_verified_jwt(c);

	ck_assert_int_eq(jwt_get_alg(jwt), alg);

	jwt_set_GET_STR(&v, "x-tenant");
	ck_assert_int_eq(jwt_header_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, "acme");

	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_header_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, jwt_alg_str(alg));

	jwt_set_GET_STR(&v, "x-unprot");
	ck_assert_int_eq(jwt_header_get(jwt, &v), JWT_VALUE_ERR_NOEXIST);

	ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	check_sig_header(c, 0, alg, NULL);

	/* Out of range. */
	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, 1, &v),
			 JWT_VALUE_ERR_INVALID);
}

/* ---- NULL arguments and a checker that never verified ---- */
START_TEST(test_args)
{
	jwt_checker_auto_t *c = NULL;
	jwt_value_t v;

	SET_OPS();

	ck_assert_ptr_null(jwt_checker_verified_jwt(NULL));
	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(NULL, 0, &v),
			 JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(v.error, JWT_VALUE_ERR_INVALID);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_sig_header_get(c, 0, NULL),
			 JWT_VALUE_ERR_INVALID);
	check_nothing(c);
}
END_TEST

/* ---- Compact, single key (and one where the key's own "alg" picks
 * the algorithm) ---- */
START_TEST(test_compact_single)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *hs = NULL, *es = NULL;
	jwk_set_t *oct, *ec;

	SET_OPS();

	oct = load_one("oct_key_256.json");
	ec = load_one("ec_key_prime256v1.json");
	hs = make_tok(JWT_ALG_HS256, jwks_item_get(oct, 0), JWT_FORMAT_COMPACT,
		      "user0", NULL, 0);
	es = make_tok(JWT_ALG_ES256, jwks_item_get(ec, 0), JWT_FORMAT_COMPACT,
		      "user1", NULL, 0);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256,
					    jwks_item_get(oct, 0)), 0);
	ck_assert_int_eq(jwt_checker_verify(c, hs), 0);
	check_single(c, JWT_ALG_HS256, "user0");

	/* jwt_checker_claim_get() still returns the pinned value, not the
	 * token's: there is none. */
	ck_assert_ptr_null(jwt_checker_claim_get(c, JWT_CLAIM_SUB));

	/* The key's own "alg" picks the algorithm. */
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_NONE,
					    jwks_item_get(ec, 0)), 0);
	ck_assert_int_eq(jwt_checker_verify(c, es), 0);
	check_single(c, JWT_ALG_ES256, "user1");

	jwks_free(oct);
	jwks_free(ec);
}
END_TEST

/* ---- Compact against a keyring, incl. a key with no "alg" ---- */
START_TEST(test_compact_ring)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *hs = NULL;
	jwk_set_t *ring;

	SET_OPS();

	/* oct_key_256_sig.json has "use":"sig" and no "alg": only the
	 * accepted token says which algorithm verified. */
	ring = load_one("oct_key_256_sig.json");
	ck_assert_int_eq(jwks_item_alg(jwks_item_get(ring, 0)), JWT_ALG_NONE);
	hs = make_tok(JWT_ALG_HS256, jwks_item_get(ring, 0),
		      JWT_FORMAT_COMPACT, "user0", NULL, 0);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
						JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c, hs), 0);
	check_single(c, JWT_ALG_HS256, "user0");
	ck_assert_ptr_eq(jwt_checker_sig_key(c, 0), jwks_item_get(ring, 0));

	/* Again, under ALL. */
	ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
						JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(c, hs), 0);
	check_single(c, JWT_ALG_HS256, "user0");

	jwks_free(ring);
}
END_TEST

/* ---- Flattened: the unprotected "header" is never returned ---- */
START_TEST(test_flattened)
{
	jwt_checker_auto_t *c = NULL, *r = NULL;
	jwt_builder_auto_t *b = NULL;
	char_auto *tok = NULL;
	jwk_set_t *ec;
	jwt_signature_t *s;

	SET_OPS();

	ec = load_one("ec_key_prime256v1.json");

	b = jwt_builder_new();
	ck_assert_ptr_nonnull(b);
	std_claims(b, "user0", NULL, 0);
	s = jwt_builder_add_signature(b, JWT_ALG_ES256, jwks_item_get(ec, 0));
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(jwt_signature_add_header_json(s, "x-unprot",
						       "\"u0\""), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, JWT_FORMAT_JSON_FLAT), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);
	ck_assert_ptr_nonnull(strstr(tok, "x-unprot"));

	/* A single key. */
	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256,
					    jwks_item_get(ec, 0)), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	check_single(c, JWT_ALG_ES256, "user0");

	/* A keyring. */
	r = jwt_checker_new();
	ck_assert_ptr_nonnull(r);
	ck_assert_int_eq(jwt_checker_setkeyring(r, ec,
						JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(r, tok), 0);
	check_single(r, JWT_ALG_ES256, "user0");

	jwks_free(ec);
}
END_TEST

/* A General token's jwt_t: claims, but no single header or algorithm. */
static void check_general(jwt_checker_t *c, const char *sub)
{
	jwt_t *jwt;
	jwt_value_t v;

	check_claims(c, sub);
	jwt = jwt_checker_verified_jwt(c);

	ck_assert_int_eq(jwt_get_alg(jwt), JWT_ALG_INVAL);
	jwt_set_GET_STR(&v, "x-tenant");
	ck_assert_int_eq(jwt_header_get(jwt, &v), JWT_VALUE_ERR_NOEXIST);
	jwt_set_GET_JSON(&v, NULL);
	ck_assert_int_eq(jwt_header_get(jwt, &v), JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.json_val, "{}");
	free(v.json_val);

	ck_assert_uint_eq(jwt_checker_sig_count(c), 2);
	check_sig_header(c, 0, JWT_ALG_ES256, "ec");
}

/* ---- General under ANY and ALL, fully and partly verified ---- */
START_TEST(test_general)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;
	jwk_set_t *ec, *rsa, *both;
	jwt_value_t v;

	SET_OPS();

	ec = load_one("ec_key_prime256v1.json");
	rsa = load_one("rsa_key_2048.json");
	both = jwks_create(NULL);
	ck_assert_ptr_nonnull(both);
	ck_assert_ptr_nonnull(jwks_load_fromfile(both,
		KEYDIR "/ec_key_prime256v1.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(both,
		KEYDIR "/rsa_key_2048.json"));

	tok = make_general(jwks_item_get(ec, 0), jwks_item_get(rsa, 0),
			   "user0", NULL, 0);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);

	/* Both keys: every signature is readable, under ANY and ALL. */
	ck_assert_int_eq(jwt_checker_setkeyring(c, both,
						JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	check_general(c, "user0");
	check_sig_header(c, 1, JWT_ALG_RS256, "rsa");

	ck_assert_int_eq(jwt_checker_setkeyring(c, both,
						JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	check_general(c, "user0");
	check_sig_header(c, 1, JWT_ALG_RS256, "rsa");

	/* Out of range. */
	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, 2, &v),
			 JWT_VALUE_ERR_INVALID);

	/* Only the EC key, ANY: accepted, but the RSA signature that did not
	 * verify is not readable. */
	ck_assert_int_eq(jwt_checker_setkeyring(c, ec,
						JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	ck_assert_int_eq(jwt_checker_sig_verified(c, 1), 0);
	check_general(c, "user0");
	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, 1, &v),
			 JWT_VALUE_ERR_INVALID);
	ck_assert_int_eq(v.error, JWT_VALUE_ERR_INVALID);

	/* Only the EC key, ALL: rejected, so nothing, although signature 0
	 * verified. */
	ck_assert_int_eq(jwt_checker_setkeyring(c, ec,
						JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
	ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
	check_nothing(c);

	jwks_free(both);
	jwks_free(rsa);
	jwks_free(ec);
}
END_TEST

/* ---- jwt_checker_verify_detached(), Compact and Flattened ---- */
START_TEST(test_detached)
{
	static const jwt_serialization_t fmts[] = {
		JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT,
	};
	const char *claims = "{\"sub\":\"user0\",\"scope\":\"read\","
			     "\"n\":42,\"flag\":true}";
	jwk_set_t *oct;
	size_t i;

	SET_OPS();

	oct = load_one("oct_key_256.json");

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_nonnull(c);
		set_str(b, 1, "x-tenant", "acme");
		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_HS256,
						    jwks_item_get(oct, 0)), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, fmts[i]), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b,
			(const unsigned char *)claims, strlen(claims)), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256,
						    jwks_item_get(oct, 0)), 0);
		ck_assert_int_eq(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)claims, strlen(claims)), 0);
		check_single(c, JWT_ALG_HS256, "user0");

		/* A detached verify that fails at once releases it. */
		ck_assert_int_ne(jwt_checker_verify_detached(c, tok, NULL, 1),
				 0);
		check_nothing(c);

		ck_assert_int_eq(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)claims, strlen(claims)), 0);
		ck_assert_ptr_nonnull(jwt_checker_verified_jwt(c));
		ck_assert_int_ne(jwt_checker_verify_detached(c, NULL,
			(const unsigned char *)claims, strlen(claims)), 0);
		check_nothing(c);

		/* The wrong payload. */
		ck_assert_int_eq(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)claims, strlen(claims)), 0);
		ck_assert_int_ne(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)"{}", 2), 0);
		check_nothing(c);
	}

	jwks_free(oct);
}
END_TEST

/* ---- An unencoded ("b64":false) payload gives an empty claim set ---- */
START_TEST(test_unencoded)
{
	static const jwt_serialization_t fmts[] = {
		JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT,
	};
	const char *doc = "{\"sub\":\"user0\"}";
	jwk_set_t *oct;
	size_t i;
	int ring;

	SET_OPS();

	oct = load_one("oct_key_256.json");

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		for (ring = 0; ring < 2; ring++) {
			jwt_builder_auto_t *b = jwt_builder_new();
			jwt_checker_auto_t *c = jwt_checker_new();
			char_auto *tok = NULL;
			jwt_value_t v;
			jwt_t *jwt;

			ck_assert_ptr_nonnull(b);
			ck_assert_ptr_nonnull(c);
			ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_HS256,
				jwks_item_get(oct, 0)), 0);
			ck_assert_int_eq(jwt_builder_set_format(b, fmts[i]), 0);
			ck_assert_int_eq(jwt_builder_setpayload(b,
				(const unsigned char *)doc, strlen(doc)), 0);
			ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
			tok = jwt_builder_generate(b);
			ck_assert_ptr_nonnull(tok);

			if (ring)
				ck_assert_int_eq(jwt_checker_setkeyring(c, oct,
					JWT_VERIFY_POLICY_ANY), 0);
			else
				ck_assert_int_eq(jwt_checker_setkey(c,
					JWT_ALG_HS256,
					jwks_item_get(oct, 0)), 0);
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

			jwt = jwt_checker_verified_jwt(c);
			ck_assert_ptr_nonnull(jwt);
			jwt_set_GET_JSON(&v, NULL);
			ck_assert_int_eq(jwt_claim_get(jwt, &v),
					 JWT_VALUE_ERR_NONE);
			ck_assert_str_eq(v.json_val, "{}");
			free(v.json_val);
			jwt_set_GET_STR(&v, "sub");
			ck_assert_int_eq(jwt_claim_get(jwt, &v),
					 JWT_VALUE_ERR_NOEXIST);

			/* The header is protected, and says "b64":false. */
			ck_assert_int_eq(jwt_get_alg(jwt), JWT_ALG_HS256);
			jwt_set_GET_BOOL(&v, "b64");
			ck_assert_int_eq(jwt_header_get(jwt, &v),
					 JWT_VALUE_ERR_NONE);
			ck_assert_int_eq(v.bool_val, 0);
			jwt_set_GET_BOOL(&v, "b64");
			ck_assert_int_eq(jwt_checker_sig_header_get(c, 0, &v),
					 JWT_VALUE_ERR_NONE);
			ck_assert_int_eq(v.bool_val, 0);
		}
	}

	jwks_free(oct);
}
END_TEST

/* ---- An unsigned token an unkeyed checker opted in to ---- */
START_TEST(test_unsigned)
{
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;
	jwt_value_t v;

	SET_OPS();

	b = jwt_builder_new();
	ck_assert_ptr_nonnull(b);
	std_claims(b, "user0", NULL, 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	checker_allow_none(c);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	check_claims(c, "user0");
	ck_assert_int_eq(jwt_get_alg(jwt_checker_verified_jwt(c)),
			 JWT_ALG_NONE);
	jwt_set_GET_STR(&v, "alg");
	ck_assert_int_eq(jwt_checker_sig_header_get(c, 0, &v),
			 JWT_VALUE_ERR_NONE);
	ck_assert_str_eq(v.str_val, "none");
}
END_TEST

static int jti_reject(const jwt_t *jwt, jwt_config_t *config, const char *jti)
{
	(void)jwt;
	(void)config;
	(void)jti;

	return 1;
}

/* Verify @good with @c (accepted), then @bad (rejected): nothing remains. */
static void good_then_bad(jwt_checker_t *c, const char *good, const char *bad)
{
	ck_assert_int_eq(jwt_checker_verify(c, good), 0);
	ck_assert_ptr_nonnull(jwt_checker_verified_jwt(c));
	ck_assert_int_ne(jwt_checker_verify(c, bad), 0);
	check_nothing(c);
}

/* ---- Every kind of failure leaves nothing to read ---- */
START_TEST(test_failures)
{
	jwk_set_t *oct, *ec, *rsa;
	int path;

	SET_OPS();

	oct = load_one("oct_key_256.json");
	ec = load_one("ec_key_prime256v1.json");
	rsa = load_one("rsa_key_2048.json");

	/* 0: Compact, single key; 1: Compact, keyring; 2: General, keyring
	 * (ANY, which only the ES256 signature can meet). */
	for (path = 0; path < 3; path++) {
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *ok = NULL, *forged = NULL, *expired = NULL;
		char_auto *jti = NULL;
		const char *req[] = { "aud" };
		const jwk_item_t *hs = jwks_item_get(oct, 0);
		const jwk_item_t *es = jwks_item_get(ec, 0);
		const jwk_item_t *rs = jwks_item_get(rsa, 0);
		char *p;

		ck_assert_ptr_nonnull(c);
		if (path == 2) {
			ok = make_general(es, rs, "user0", NULL, 0);
			expired = make_general(es, rs, "user0", NULL, TS_CONST);
			jti = make_general(es, rs, "user0", "id-1", 0);
		} else {
			ok = make_tok(JWT_ALG_HS256, hs, JWT_FORMAT_COMPACT,
				      "user0", NULL, 0);
			expired = make_tok(JWT_ALG_HS256, hs,
					   JWT_FORMAT_COMPACT, "user0", NULL,
					   TS_CONST);
			jti = make_tok(JWT_ALG_HS256, hs, JWT_FORMAT_COMPACT,
				       "user0", "id-1", 0);
		}
		if (path == 0)
			ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256,
							    hs), 0);
		else
			ck_assert_int_eq(jwt_checker_setkeyring(c,
				path == 2 ? ec : oct, JWT_VERIFY_POLICY_ANY),
				0);

		/* A bad signature: flip a character of the first one. */
		forged = strdup(ok);
		ck_assert_ptr_nonnull(forged);
		if (path == 2) {
			p = strstr(forged, "\"signature\":\"");
			ck_assert_ptr_nonnull(p);
			p += strlen("\"signature\":\"");
		} else {
			p = forged + strlen(forged) - 2;
		}
		*p = (*p == 'A') ? 'B' : 'A';
		good_then_bad(c, ok, forged);

		/* An expired token, whose signature (on the keyring paths,
		 * which check it first) verifies. */
		good_then_bad(c, ok, expired);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0),
				 path == 0 ? 0 : 1);

		/* A "jti" the jti callback rejects, then a token without one,
		 * rejected while the callback is set. */
		ck_assert_int_eq(jwt_checker_verify(c, ok), 0);
		ck_assert_int_eq(jwt_checker_setjti(c, jti_reject, NULL), 0);
		ck_assert_int_ne(jwt_checker_verify(c, jti), 0);
		check_nothing(c);
		ck_assert_int_eq(jwt_checker_setjti(c, NULL, NULL), 0);
		ck_assert_int_eq(jwt_checker_verify(c, ok), 0);
		ck_assert_int_eq(jwt_checker_setjti(c, jti_reject, NULL), 0);
		ck_assert_int_ne(jwt_checker_verify(c, ok), 0);
		check_nothing(c);
		ck_assert_int_eq(jwt_checker_setjti(c, NULL, NULL), 0);

		/* A pinned claim that does not match. */
		ck_assert_int_eq(jwt_checker_verify(c, ok), 0);
		ck_assert_int_eq(jwt_checker_claim_set(c, JWT_CLAIM_SUB,
						       "other"), 0);
		ck_assert_int_ne(jwt_checker_verify(c, ok), 0);
		check_nothing(c);
		ck_assert_int_eq(jwt_checker_claim_del(c, JWT_CLAIM_SUB), 0);

		/* A missing required claim. */
		ck_assert_int_eq(jwt_checker_verify(c, ok), 0);
		ck_assert_int_eq(jwt_checker_require(c, req, 1), 0);
		ck_assert_int_ne(jwt_checker_verify(c, ok), 0);
		check_nothing(c);
		ck_assert_int_eq(jwt_checker_require(c, NULL, 0), 0);

		/* NULL, empty and malformed tokens. */
		good_then_bad(c, ok, NULL);
		good_then_bad(c, ok, "");
		good_then_bad(c, ok, "not-a-token");
		good_then_bad(c, ok, "{\"payload\":\"\"}");
	}

	jwks_free(rsa);
	jwks_free(ec);
	jwks_free(oct);
}
END_TEST

/* What callbacks saw of the checker's accepted token while they ran. */
static struct {
	jwt_checker_t *c;
	int calls;
	int saw_jwt;
	int saw_hdr;
	int saw_old_sub;
} cbs;

static void cb_look(const jwt_t *jwt)
{
	jwt_value_t v;

	cbs.calls++;
	if (jwt_checker_verified_jwt(cbs.c) != NULL)
		cbs.saw_jwt++;
	jwt_set_GET_STR(&v, "alg");
	if (jwt_checker_sig_header_get(cbs.c, 0, &v) != JWT_VALUE_ERR_INVALID)
		cbs.saw_hdr++;
	/* The jwt_t passed in holds this token's claims, never "user0"'s. */
	jwt_set_GET_STR(&v, "sub");
	if (jwt_claim_get((jwt_t *)jwt, &v) == JWT_VALUE_ERR_NONE &&
	    !strcmp(v.str_val, "user0"))
		cbs.saw_old_sub++;
}

static int verify_cb(jwt_t *jwt, jwt_config_t *config)
{
	(void)config;
	cb_look(jwt);

	return 0;
}

static int jti_cb(const jwt_t *jwt, jwt_config_t *config, const char *jti)
{
	(void)config;
	(void)jti;
	cb_look(jwt);

	return 0;
}

/* Verify @tok with @c, whose verify and jti callbacks are set: it returns
 * @expect (0 or 1), and they run @calls times in all and see nothing of the
 * token @c accepted before. */
static void cb_verify(jwt_checker_t *c, const char *tok, int expect,
		      int calls)
{
	memset(&cbs, 0, sizeof(cbs));
	cbs.c = c;
	ck_assert_int_eq(jwt_checker_verify(c, tok) ? 1 : 0, expect);
	ck_assert_int_eq(cbs.calls, calls);
	ck_assert_int_eq(cbs.saw_jwt, 0);
	ck_assert_int_eq(cbs.saw_hdr, 0);
	ck_assert_int_eq(cbs.saw_old_sub, 0);
}

/* ---- Lifetime: the next verify releases it; callbacks never see it ---- */
START_TEST(test_lifetime)
{
	jwk_set_t *oct, *ec, *rsa, *both;
	int path;

	SET_OPS();

	oct = load_one("oct_key_256.json");
	ec = load_one("ec_key_prime256v1.json");
	rsa = load_one("rsa_key_2048.json");
	both = jwks_create(NULL);
	ck_assert_ptr_nonnull(both);
	ck_assert_ptr_nonnull(jwks_load_fromfile(both,
		KEYDIR "/ec_key_prime256v1.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(both,
		KEYDIR "/rsa_key_2048.json"));

	/* 0: Compact, single key; 1: Compact, keyring; 2: General, keyring
	 * (ALL). */
	for (path = 0; path < 3; path++) {
		jwt_checker_t *c = jwt_checker_new();
		char_auto *t0 = NULL, *t1 = NULL, *nojti = NULL;
		const jwk_item_t *hs = jwks_item_get(oct, 0);
		const jwk_item_t *es = jwks_item_get(ec, 0);
		const jwk_item_t *rs = jwks_item_get(rsa, 0);
		int n_sigs = path == 2 ? 2 : 1;

		ck_assert_ptr_nonnull(c);
		if (path == 2) {
			t0 = make_general(es, rs, "user0", "id-0", 0);
			t1 = make_general(es, rs, "user1", "id-1", 0);
			nojti = make_general(es, rs, "user1", NULL, 0);
			ck_assert_int_eq(jwt_checker_setkeyring(c, both,
				JWT_VERIFY_POLICY_ALL), 0);
		} else {
			t0 = make_tok(JWT_ALG_HS256, hs, JWT_FORMAT_COMPACT,
				      "user0", "id-0", 0);
			t1 = make_tok(JWT_ALG_HS256, hs, JWT_FORMAT_COMPACT,
				      "user1", "id-1", 0);
			nojti = make_tok(JWT_ALG_HS256, hs, JWT_FORMAT_COMPACT,
					 "user1", NULL, 0);
			if (path == 0)
				ck_assert_int_eq(jwt_checker_setkey(c,
					JWT_ALG_HS256, hs), 0);
			else
				ck_assert_int_eq(jwt_checker_setkeyring(c, oct,
					JWT_VERIFY_POLICY_ANY), 0);
		}

		/* The next successful verify replaces it. */
		ck_assert_int_eq(jwt_checker_verify(c, t0), 0);
		check_claims(c, "user0");
		ck_assert_int_eq(jwt_checker_verify(c, t1), 0);
		check_claims(c, "user1");

		/* Right after t0 was accepted, the callbacks on the next
		 * verify see none of it, accepted or not: the verify callback
		 * runs once per signature, the jti callback once, last. */
		memset(&cbs, 0, sizeof(cbs));
		cbs.c = c;
		ck_assert_int_eq(jwt_checker_setcb(c, verify_cb, NULL), 0);
		ck_assert_int_eq(jwt_checker_setjti(c, jti_cb, NULL), 0);
		ck_assert_int_eq(jwt_checker_verify(c, t0), 0);
		cb_verify(c, t1, 0, n_sigs + 1);
		check_claims(c, "user1");

		ck_assert_int_eq(jwt_checker_verify(c, t0), 0);
		cb_verify(c, nojti, 1, n_sigs);
		check_nothing(c);
		ck_assert_int_eq(jwt_checker_setcb(c, NULL, NULL), 0);
		ck_assert_int_eq(jwt_checker_setjti(c, NULL, NULL), 0);

		/* A verify that fails at once releases it. */
		ck_assert_int_eq(jwt_checker_verify(c, t0), 0);
		ck_assert_int_ne(jwt_checker_verify(c, NULL), 0);
		check_nothing(c);

		/* jwt_checker_free() releases a token it still holds (ASan
		 * and memcheck would report a leak). */
		ck_assert_int_eq(jwt_checker_verify(c, t0), 0);
		ck_assert_ptr_nonnull(jwt_checker_verified_jwt(c));
		jwt_checker_free(c);
	}

	jwks_free(both);
	jwks_free(rsa);
	jwks_free(ec);
	jwks_free(oct);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_verified");

	tcase_add_loop_test(tc_core, test_args, 0, i);
	tcase_add_loop_test(tc_core, test_compact_single, 0, i);
	tcase_add_loop_test(tc_core, test_compact_ring, 0, i);
	tcase_add_loop_test(tc_core, test_flattened, 0, i);
	tcase_add_loop_test(tc_core, test_general, 0, i);
	tcase_add_loop_test(tc_core, test_detached, 0, i);
	tcase_add_loop_test(tc_core, test_unencoded, 0, i);
	tcase_add_loop_test(tc_core, test_unsigned, 0, i);
	tcase_add_loop_test(tc_core, test_failures, 0, i);
	tcase_add_loop_test(tc_core, test_lifetime, 0, i);

	tcase_set_timeout(tc_core, 60);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Checker Verified Token (#362)");
}
