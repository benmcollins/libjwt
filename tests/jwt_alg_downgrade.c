/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Same-family algorithm downgrade in the Compact verify path.
 *
 * On the pinned path of __verify_config_post() -- both config->alg and
 * config->key->alg set and equal -- the token's own alg (jwt->alg) was never
 * compared against the pinned alg, and the jwt_alg_required_kty() backstop is
 * only family-granular (every RSn/PSn alg maps to RSA). So a token presenting
 * "RS512" verified against a key pinned as "RS256" -- same family, valid
 * signature -- was accepted, i.e. a pinned verifier accepted an algorithm it
 * never pinned. Not a forgery; a policy/conformance gap. These tests pin it
 * shut and guard the legitimate (matching) cases against over-rejection.
 *
 * Runs under each crypto backend (SET_OPS); RSA only, so JSON-backend-agnostic.
 */

static jwk_set_t *load(const char *file)
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

/* Sign a token with the given alg and serialization using a key that carries no
 * "alg" hint (so the builder lets us choose any RSA alg for the same modulus). */
static char *sign(const jwk_item_t *key, jwt_alg_t alg, jwt_serialization_t fmt)
{
	jwt_builder_auto_t *b = jwt_builder_new();

	ck_assert_int_eq(jwt_builder_setkey(b, alg, key), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, fmt), 0);

	return jwt_builder_generate(b);
}

/* The same downgrade check on both serializations: the Compact path runs
 * through __verify_config_post(), the JSON path through verify_entry() /
 * try_candidate(). jwt_checker_verify() auto-detects the format. */
START_TEST(test_same_family_downgrade)
{
	jwk_set_t *sks, *vks;
	const jwk_item_t *skey, *vkey;
	jwt_serialization_t fmts[] = { JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT };
	size_t i;

	SET_OPS();

	/* Same 2048-bit RSA modulus, two views: one with no "alg" (to sign any
	 * RSA alg), one pinned to RS256 (to verify). */
	sks = load("rsa_key_2048_no_alg.json");
	skey = jwks_item_get(sks, 0);
	ck_assert_ptr_nonnull(skey);

	vks = load("rsa_key_2048.json"); /* carries "alg":"RS256" */
	vkey = jwks_item_get(vks, 0);
	ck_assert_ptr_nonnull(vkey);

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		char_auto *rs512 = NULL, *rs256 = NULL;
		jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL;

		/* A genuinely RS512-signed token (valid signature on this key). */
		rs512 = sign(skey, JWT_ALG_RS512, fmts[i]);
		ck_assert_ptr_nonnull(rs512);

		/* THE GAP: pin RS256, present RS512. The signature is otherwise
		 * valid, so without the alg pin this verifies; it must be rejected. */
		c1 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_RS256, vkey), 0);
		ck_assert_int_ne(jwt_checker_verify(c1, rs512), 0);

		/* Positive control 1: pin RS256, present RS256 -> accepted. */
		rs256 = sign(skey, JWT_ALG_RS256, fmts[i]);
		ck_assert_ptr_nonnull(rs256);
		c2 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_RS256, vkey), 0);
		ck_assert_int_eq(jwt_checker_verify(c2, rs256), 0);

		/* Positive control 2: legitimately accept RS512 (via the no-alg key,
		 * which pins no alg) -> the pin does not over-reject. */
		c3 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c3, JWT_ALG_RS512, skey), 0);
		ck_assert_int_eq(jwt_checker_verify(c3, rs512), 0);
	}

	jwks_free(sks);
	jwks_free(vks);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_alg_downgrade");

	tcase_add_loop_test(tc_core, test_same_family_downgrade, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT same-family algorithm downgrade in verify");
}
