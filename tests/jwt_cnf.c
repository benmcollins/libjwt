/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for the RFC 7800 "cnf" (confirmation) claim helpers:
 * jwt_builder_setcnf_jkt() / _jwk() / jwt_builder_setcnf() and jwt_get_cnf().
 * The token is signed and verified with one EC P-256 key (ES256 works on every
 * backend); the same key's public thumbprint is the proof-of-possession value. */

static jwk_set_t *load_named(const char *file)
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

/* The proof-of-possession key bound via cnf (its thumbprint/export are used). */
static jwk_set_t *load_key(void)
{
	return load_named("ec_key_prime256v1.json");
}

/* A symmetric key used only to sign the test tokens. HS256 works on every
 * backend, so the cnf round-trip tests don't depend on a particular signing
 * algorithm (the cnf helpers are signature-agnostic). */
static jwk_set_t *load_signer(void)
{
	return load_named("oct_key_256.json");
}

/* Get the builder's current "cnf" claim as a serialized JSON string. */
static char *get_builder_cnf(jwt_builder_t *builder)
{
	jwt_value_t jval;

	jwt_set_GET_JSON(&jval, "cnf");
	if (jwt_builder_claim_get(builder, &jval) != JWT_VALUE_ERR_NONE)
		return NULL;

	return jval.json_val;
}

START_TEST(test_setcnf_jkt)
{
	jwk_set_t *set = load_key();
	const jwk_item_t *key = jwks_item_get(set, 0);
	jwt_builder_auto_t *builder = NULL;
	char_auto *tp = NULL;
	char_auto *cnf = NULL;
	char expected[128];

	SET_OPS();

	tp = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp);
	snprintf(expected, sizeof(expected), "{\"jkt\":\"%s\"}", tp);

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);

	ck_assert_int_eq(jwt_builder_setcnf_jkt(builder, key), 0);

	cnf = get_builder_cnf(builder);
	ck_assert_ptr_nonnull(cnf);
	ck_assert_str_eq(cnf, expected);

	jwks_free(set);
}
END_TEST

START_TEST(test_setcnf_generic_and_single_member)
{
	jwk_set_t *set = load_key();
	const jwk_item_t *key = jwks_item_get(set, 0);
	jwt_builder_auto_t *builder = NULL;
	char_auto *c1 = NULL, *c2 = NULL, *c3 = NULL;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);

	/* A string member (e.g. the RFC 8705 mTLS confirmation). */
	ck_assert_int_eq(jwt_builder_setcnf(builder, "x5t#S256", "abc123"), 0);
	c1 = get_builder_cnf(builder);
	ck_assert_str_eq(c1, "{\"x5t#S256\":\"abc123\"}");

	/* A second setter REPLACES cnf: it must still carry exactly one member. */
	ck_assert_int_eq(jwt_builder_setcnf(builder, "kid", "key-1"), 0);
	c2 = get_builder_cnf(builder);
	ck_assert_str_eq(c2, "{\"kid\":\"key-1\"}");

	/* jkt likewise replaces. */
	ck_assert_int_eq(jwt_builder_setcnf_jkt(builder, key), 0);
	c3 = get_builder_cnf(builder);
	ck_assert(!strncmp(c3, "{\"jkt\":\"", 8));
	/* exactly one member: one ':' and no ',' */
	ck_assert_ptr_null(strchr(c3, ','));

	jwks_free(set);
}
END_TEST

START_TEST(test_setcnf_jwk)
{
	jwk_set_t *set = load_key();
	const jwk_item_t *key = jwks_item_get(set, 0);
	jwt_builder_auto_t *builder = NULL;
	char_auto *cnf = NULL;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);

	ck_assert_int_eq(jwt_builder_setcnf_jwk(builder, key), 0);

	cnf = get_builder_cnf(builder);
	ck_assert_ptr_nonnull(cnf);

	/* cnf = {"jwk": <public EC JWK>} : has the public members, not "d". */
	ck_assert(strstr(cnf, "\"jwk\":{") != NULL);
	ck_assert(strstr(cnf, "\"kty\":\"EC\"") != NULL);
	ck_assert(strstr(cnf, "\"crv\":\"P-256\"") != NULL);
	ck_assert(strstr(cnf, "\"x\":") != NULL);
	ck_assert(strstr(cnf, "\"d\":") == NULL);

	jwks_free(set);
}
END_TEST

/* Captures what the verify callback reads from the token's cnf. */
struct cnf_seen {
	char *jkt;		/* cnf.jkt value (must match)	*/
	int missing_is_null;	/* jwt_get_cnf(absent) == NULL	*/
	int object_is_null;	/* jwt_get_cnf("jwk" object) == NULL when present */
	int ran;
};

static int verify_jkt_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct cnf_seen *s = config->ctx;

	s->ran = 1;
	s->jkt = jwt_get_cnf(jwt, "jkt");
	s->missing_is_null = (jwt_get_cnf(jwt, "nope") == NULL);
	return 0;
}

static int verify_jwk_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct cnf_seen *s = config->ctx;

	s->ran = 1;
	/* "jwk" is an object, not a string -> the string getter returns NULL. */
	s->object_is_null = (jwt_get_cnf(jwt, "jwk") == NULL);
	return 0;
}

static int verify_nocnf_cb(jwt_t *jwt, jwt_config_t *config)
{
	struct cnf_seen *s = config->ctx;

	s->ran = 1;
	/* No "cnf" claim at all -> NULL. */
	s->missing_is_null = (jwt_get_cnf(jwt, "jkt") == NULL);
	return 0;
}

START_TEST(test_get_cnf_roundtrip)
{
	jwk_set_t *set = load_key();
	jwk_set_t *sset = load_signer();
	const jwk_item_t *key = jwks_item_get(set, 0);
	const jwk_item_t *skey = jwks_item_get(sset, 0);
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *tp = NULL;
	char_auto *token = NULL;
	struct cnf_seen seen;

	SET_OPS();

	tp = jwks_item_thumbprint(key, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp);

	/* Issue an HS256 token bound to the EC key via cnf.jkt. */
	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_HS256, skey), 0);
	ck_assert_int_eq(jwt_builder_setcnf_jkt(builder, key), 0);
	token = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(token);

	/* Verify and read cnf.jkt from the callback's jwt_t. */
	memset(&seen, 0, sizeof(seen));
	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_HS256, skey), 0);
	ck_assert_int_eq(jwt_checker_setcb(checker, verify_jkt_cb, &seen), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	ck_assert_int_eq(seen.ran, 1);
	ck_assert_ptr_nonnull(seen.jkt);
	ck_assert_str_eq(seen.jkt, tp);
	ck_assert_int_eq(seen.missing_is_null, 1);
	free(seen.jkt);

	jwks_free(sset);
	jwks_free(set);
}
END_TEST

START_TEST(test_get_cnf_object_member)
{
	jwk_set_t *set = load_key();
	jwk_set_t *sset = load_signer();
	const jwk_item_t *key = jwks_item_get(set, 0);
	const jwk_item_t *skey = jwks_item_get(sset, 0);
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	struct cnf_seen seen;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_HS256, skey), 0);
	ck_assert_int_eq(jwt_builder_setcnf_jwk(builder, key), 0);
	token = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(token);

	memset(&seen, 0, sizeof(seen));
	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_HS256, skey), 0);
	ck_assert_int_eq(jwt_checker_setcb(checker, verify_jwk_cb, &seen), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	ck_assert_int_eq(seen.ran, 1);
	ck_assert_int_eq(seen.object_is_null, 1);

	jwks_free(sset);
	jwks_free(set);
}
END_TEST

START_TEST(test_get_cnf_absent)
{
	jwk_set_t *sset = load_signer();
	const jwk_item_t *skey = jwks_item_get(sset, 0);
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *token = NULL;
	struct cnf_seen seen;

	SET_OPS();

	/* A token with no "cnf" at all. */
	builder = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_HS256, skey), 0);
	token = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(token);

	memset(&seen, 0, sizeof(seen));
	checker = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_HS256, skey), 0);
	ck_assert_int_eq(jwt_checker_setcb(checker, verify_nocnf_cb, &seen), 0);
	ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

	ck_assert_int_eq(seen.ran, 1);
	ck_assert_int_eq(seen.missing_is_null, 1);

	jwks_free(sset);
}
END_TEST

START_TEST(test_errors)
{
	jwk_set_t *set = load_key();
	const jwk_item_t *key = jwks_item_get(set, 0);
	jwt_builder_auto_t *builder = NULL;
	jwk_set_t *seed_set;
	const jwk_item_t *seed_key;
	char *p;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);

	/* NULL / empty arguments. */
	ck_assert_int_ne(jwt_builder_setcnf_jkt(NULL, key), 0);
	ck_assert_int_ne(jwt_builder_setcnf_jkt(builder, NULL), 0);
	ck_assert_int_ne(jwt_builder_setcnf_jwk(NULL, key), 0);
	ck_assert_int_ne(jwt_builder_setcnf_jwk(builder, NULL), 0);
	ck_assert_int_ne(jwt_builder_setcnf(NULL, "kid", "v"), 0);
	ck_assert_int_ne(jwt_builder_setcnf(builder, NULL, "v"), 0);
	ck_assert_int_ne(jwt_builder_setcnf(builder, "", "v"), 0);
	ck_assert_int_ne(jwt_builder_setcnf(builder, "kid", NULL), 0);

	ck_assert_ptr_null(jwt_get_cnf(NULL, "jkt"));

	/* A seed-only OKP key (Ed448, "d" with no "x") can't be thumbprinted,
	 * so jkt binding fails cleanly. */
	ret = asprintf(&p, KEYDIR "/eddsa_key_ed448.json");
	ck_assert_int_gt(ret, 0);
	seed_set = jwks_create_fromfile(p);
	free(p);
	ck_assert_ptr_nonnull(seed_set);
	seed_key = jwks_item_get(seed_set, 0);
	ck_assert_ptr_nonnull(seed_key);
	ck_assert_int_ne(jwt_builder_setcnf_jkt(builder, seed_key), 0);

	jwks_free(seed_set);
	jwks_free(set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_cnf");

	tcase_add_loop_test(tc_core, test_setcnf_jkt, 0, i);
	tcase_add_loop_test(tc_core, test_setcnf_generic_and_single_member, 0, i);
	tcase_add_loop_test(tc_core, test_setcnf_jwk, 0, i);
	tcase_add_loop_test(tc_core, test_get_cnf_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, test_get_cnf_object_member, 0, i);
	tcase_add_loop_test(tc_core, test_get_cnf_absent, 0, i);
	tcase_add_loop_test(tc_core, test_errors, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT cnf (RFC 7800) Confirmation Claim");
}
