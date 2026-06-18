/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Tests for the RFC 7638 JWK Thumbprint and RFC 9278 Thumbprint URI:
 * jwks_item_thumbprint() and jwks_item_thumbprint_uri(). The expected values
 * are deterministic across every crypto and JSON backend, so each test runs
 * under the full jwt_test_ops[] loop. */

/* RFC 7638 Section 3.1 example JWK and its published thumbprint. The extra
 * members ("alg", "kid") are NOT part of the thumbprint and must be ignored. */
static const char rfc7638_jwk[] =
	"{\"kty\":\"RSA\","
	"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"
	"wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9y"
	"BXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7"
	"d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2N"
	"cRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
	"\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

static const char rfc7638_thumb[] =
	"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

static const char *URN_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:";

static jwk_set_t *load_set(const char *file)
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

START_TEST(test_rfc7638_vector)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	char_auto *tp = NULL;
	char_auto *tp0 = NULL;
	char_auto *uri = NULL;

	SET_OPS();

	set = jwks_create(rfc7638_jwk);
	ck_assert_ptr_nonnull(set);
	ck_assert(!jwks_error(set));

	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);

	/* Explicit SHA-256 and the zero (default) selector must both equal the
	 * RFC value (JWK_THUMBPRINT_SHA256 is 0). */
	tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp);
	ck_assert_str_eq(tp, rfc7638_thumb);

	tp0 = jwks_item_thumbprint(item, 0);
	ck_assert_ptr_nonnull(tp0);
	ck_assert_str_eq(tp0, rfc7638_thumb);

	uri = jwks_item_thumbprint_uri(item, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(uri);
	ck_assert_str_eq(uri,
		"urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
		"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");

	jwks_free(set);
}
END_TEST

/* Known SHA-256 thumbprints for the standard fixtures, one per key type. */
static const struct {
	const char *file;
	const char *thumb;
} known[] = {
	{ "ec_key_prime256v1.json",  "dcqGJi_pttovbuO9Lefa_iDKSnhrviqfEWPhjKkzTgs" },
	{ "rsa_key_2048.json",       "Fqs2Gji6uQfnAew4-CpkIQVlUVqLMRCmecl5ddMwVaA" },
	{ "oct_key_256.json",        "CqF3NtBIm-AK4Ik0wgHcKk5vLKjxQMrLFuiF4BvHcho" },
	{ "eddsa_key_ed25519.json",  "yP8YONwTmFovdfeOfp9y5u_lxzP7Y3JAmpUgeNnXFS8" },
};

START_TEST(test_known_values)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(known); i++) {
		jwk_set_t *set = load_set(known[i].file);
		const jwk_item_t *item = jwks_item_get(set, 0);
		char_auto *tp = NULL;

		ck_assert_ptr_nonnull(item);
		ck_assert(!jwks_item_error(item));

		tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
		ck_assert_ptr_nonnull(tp);
		ck_assert_str_eq(tp, known[i].thumb);

		jwks_free(set);
	}
}
END_TEST

/* The thumbprint covers only public members, so a private key and its public
 * counterpart must produce the identical thumbprint. */
static const struct {
	const char *priv;
	const char *pub;
} pairs[] = {
	{ "ec_key_prime256v1.json", "ec_key_prime256v1_pub.json" },
	{ "eddsa_key_ed25519.json", "eddsa_key_ed25519_pub.json" },
};

START_TEST(test_public_equals_private)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		jwk_set_t *sp = load_set(pairs[i].priv);
		jwk_set_t *su = load_set(pairs[i].pub);
		char_auto *tp = jwks_item_thumbprint(jwks_item_get(sp, 0),
						     JWK_THUMBPRINT_SHA256);
		char_auto *tu = jwks_item_thumbprint(jwks_item_get(su, 0),
						     JWK_THUMBPRINT_SHA256);

		ck_assert_ptr_nonnull(tp);
		ck_assert_ptr_nonnull(tu);
		ck_assert_str_eq(tp, tu);

		jwks_free(sp);
		jwks_free(su);
	}
}
END_TEST

START_TEST(test_seed_only_okp_null)
{
	jwk_set_t *set;
	const jwk_item_t *item;

	SET_OPS();

	/* The Ed448 fixture is a seed-only private OKP key (it has "d" but no
	 * "x"). The thumbprint requires the public "x" member, so it must fail
	 * cleanly (return NULL, never crash). */
	set = load_set("eddsa_key_ed448.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);

	ck_assert_ptr_null(jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256));
	ck_assert_ptr_null(jwks_item_thumbprint_uri(item, JWK_THUMBPRINT_SHA256));

	jwks_free(set);
}
END_TEST

START_TEST(test_hash_sizes)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	char_auto *t256 = NULL;
	char_auto *t384 = NULL;
	char_auto *t512 = NULL;
	char_auto *u384 = NULL;
	char_auto *u512 = NULL;
	size_t plen = strlen(URN_PREFIX);

	SET_OPS();

	set = load_set("ec_key_prime256v1.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);

	t256 = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
	t384 = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA384);
	t512 = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA512);
	ck_assert_ptr_nonnull(t256);
	ck_assert_ptr_nonnull(t384);
	ck_assert_ptr_nonnull(t512);

	/* base64url without padding: 32 -> 43, 48 -> 64, 64 -> 86 chars. */
	ck_assert_uint_eq(strlen(t256), 43);
	ck_assert_uint_eq(strlen(t384), 64);
	ck_assert_uint_eq(strlen(t512), 86);

	/* A different hash size yields a different value. */
	ck_assert(strcmp(t256, t384) != 0);

	u384 = jwks_item_thumbprint_uri(item, JWK_THUMBPRINT_SHA384);
	u512 = jwks_item_thumbprint_uri(item, JWK_THUMBPRINT_SHA512);
	ck_assert_ptr_nonnull(u384);
	ck_assert_ptr_nonnull(u512);
	ck_assert(!strncmp(u384, URN_PREFIX, plen));
	ck_assert(!strncmp(u384 + plen, "sha-384:", 8));
	ck_assert(!strncmp(u512 + plen, "sha-512:", 8));
	/* The URI must carry the bare thumbprint after the "sha-NNN:" label. */
	ck_assert_str_eq(u384 + plen + 8, t384);

	jwks_free(set);
}
END_TEST

START_TEST(test_errors)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	char_auto *tp = NULL;

	SET_OPS();

	/* NULL item */
	ck_assert_ptr_null(jwks_item_thumbprint(NULL, JWK_THUMBPRINT_SHA256));
	ck_assert_ptr_null(jwks_item_thumbprint_uri(NULL, JWK_THUMBPRINT_SHA256));

	set = load_set("ec_key_prime256v1.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);

	/* Out-of-range hash selector. */
	ck_assert_ptr_null(jwks_item_thumbprint(item, (jwk_thumbprint_alg_t)100));
	ck_assert_ptr_null(jwks_item_thumbprint_uri(item,
						    (jwk_thumbprint_alg_t)100));

	/* A valid call still works after the rejected ones. */
	tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp);

	jwks_free(set);
}
END_TEST

START_TEST(test_find_bythumbprint)
{
	jwk_set_t *set;
	char *p_ec, *p_ed;
	const jwk_item_t *found, *ec_item, *ed_item;
	char_auto *tp_ec = NULL;
	char_auto *uri_ed = NULL;
	int r;

	SET_OPS();

	/* Build a two-key set: EC P-256 + Ed25519 (loaded into one set). */
	r = asprintf(&p_ec, KEYDIR "/ec_key_prime256v1.json");
	ck_assert_int_gt(r, 0);
	r = asprintf(&p_ed, KEYDIR "/eddsa_key_ed25519.json");
	ck_assert_int_gt(r, 0);

	set = jwks_load_fromfile(NULL, p_ec);
	ck_assert_ptr_nonnull(set);
	ck_assert_ptr_nonnull(jwks_load_fromfile(set, p_ed));
	free(p_ec);
	free(p_ed);
	ck_assert(!jwks_error(set));
	ck_assert_uint_eq(jwks_item_count(set), 2);

	ec_item = jwks_item_get(set, 0);
	ed_item = jwks_item_get(set, 1);

	/* Find the EC key by its bare SHA-256 thumbprint. */
	tp_ec = jwks_item_thumbprint(ec_item, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp_ec);
	found = jwks_find_bythumbprint(set, JWK_THUMBPRINT_SHA256, tp_ec);
	ck_assert_ptr_eq(found, ec_item);

	/* Find the Ed25519 key by its (SHA-384) thumbprint URI. */
	uri_ed = jwks_item_thumbprint_uri(ed_item, JWK_THUMBPRINT_SHA384);
	ck_assert_ptr_nonnull(uri_ed);
	found = jwks_find_bythumbprint_uri(set, uri_ed);
	ck_assert_ptr_eq(found, ed_item);

	/* Right value, wrong hash -> no match. */
	ck_assert_ptr_null(jwks_find_bythumbprint(set, JWK_THUMBPRINT_SHA512,
						  tp_ec));

	/* Negative and bad-input paths. */
	ck_assert_ptr_null(jwks_find_bythumbprint(set, JWK_THUMBPRINT_SHA256,
						  "nomatch"));
	ck_assert_ptr_null(jwks_find_bythumbprint(NULL, JWK_THUMBPRINT_SHA256,
						  tp_ec));
	ck_assert_ptr_null(jwks_find_bythumbprint(set, JWK_THUMBPRINT_SHA256,
						  NULL));
	ck_assert_ptr_null(jwks_find_bythumbprint_uri(NULL, uri_ed));
	ck_assert_ptr_null(jwks_find_bythumbprint_uri(set, NULL));
	/* Wrong URN prefix, unknown hash label, and valid-but-unmatched. */
	ck_assert_ptr_null(jwks_find_bythumbprint_uri(set, "not-a-uri"));
	ck_assert_ptr_null(jwks_find_bythumbprint_uri(set,
		"urn:ietf:params:oauth:jwk-thumbprint:sha-999:abc"));
	ck_assert_ptr_null(jwks_find_bythumbprint_uri(set,
		"urn:ietf:params:oauth:jwk-thumbprint:sha-256:nomatch"));

	jwks_free(set);
}
END_TEST

#ifdef LIBJWT_HAVE_ML_DSA
/* Known SHA-256 thumbprints for the ML-DSA (AKP) fixtures. The digest is over
 * the public members ("alg","kty","pub") and is backend independent. */
static const struct {
	const char *file;
	const char *thumb;
} akp_known[] = {
	{ "mldsa_key_44.json",     "xxGwBakMZvovG1w3N7H6HRyppdaD7RkeKhsjtRZsyeA" },
	{ "mldsa_key_44_pub.json", "xxGwBakMZvovG1w3N7H6HRyppdaD7RkeKhsjtRZsyeA" },
	{ "mldsa_key_65.json",     "ZlqlfBlPyndAYX9Bav1t7QPDoguca-O5n5FW5Kv9HXs" },
	{ "mldsa_key_87.json",     "9ljbLP6hu3Z-N3QsolhMGSUwctjOuM4graYlTXgB_xQ" },
};

START_TEST(test_akp_values)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(akp_known); i++) {
		jwk_set_t *set = load_set(akp_known[i].file);
		const jwk_item_t *item = jwks_item_get(set, 0);
		char_auto *tp = NULL;

		ck_assert_ptr_nonnull(item);

		/* A backend that cannot import ML-DSA at runtime (e.g. a GnuTLS
		 * without leancrypto) flags the item; skip it. Any backend that
		 * does import the key yields the same backend-independent value. */
		if (jwks_item_error(item)) {
			jwks_free(set);
			continue;
		}

		tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
		ck_assert_ptr_nonnull(tp);
		ck_assert_str_eq(tp, akp_known[i].thumb);

		jwks_free(set);
	}
}
END_TEST
#endif

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_thumbprint");

	tcase_add_loop_test(tc_core, test_rfc7638_vector, 0, i);
	tcase_add_loop_test(tc_core, test_known_values, 0, i);
	tcase_add_loop_test(tc_core, test_public_equals_private, 0, i);
	tcase_add_loop_test(tc_core, test_seed_only_okp_null, 0, i);
	tcase_add_loop_test(tc_core, test_hash_sizes, 0, i);
	tcase_add_loop_test(tc_core, test_errors, 0, i);
	tcase_add_loop_test(tc_core, test_find_bythumbprint, 0, i);
#ifdef LIBJWT_HAVE_ML_DSA
	tcase_add_loop_test(tc_core, test_akp_values, 0, i);
#endif

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWK Thumbprint (RFC 7638 / RFC 9278)");
}
