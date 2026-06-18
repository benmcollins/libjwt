/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{8725} typ media-type helper + algorithm allowlist (issue #312). Runs
 * under each crypto backend (SET_OPS) and both JSON backends. */

static jwk_set_t *load_ec(void)
{
	char *path;
	jwk_set_t *set;
	int ret;

	ret = asprintf(&path, KEYDIR "/ec_key_prime256v1.json");
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

/* Build an ES256 token with the given "typ" (NULL for none) and format. */
static char *gen(const jwk_item_t *ec, const char *typ, jwt_serialization_t fmt)
{
	jwt_builder_auto_t *b = jwt_builder_new();

	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	if (typ != NULL)
		ck_assert_int_eq(jwt_builder_settyp(b, typ), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, fmt), 0);

	return jwt_builder_generate(b);
}

START_TEST(test_typ)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	char_auto *tok = NULL;
	jwt_serialization_t fmts[] = { JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT };
	size_t i;

	SET_OPS();
	ks = load_ec();
	ec = jwks_item_get(ks, 0);

	/* Cover both the Compact and JSON verify paths. */
	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL, *c4 = NULL;

		tok = gen(ec, "at+jwt", fmts[i]);
		ck_assert_ptr_nonnull(tok);

		/* Exact, case-insensitive, and application/-prefixed all accept. */
		c1 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_expect_typ(c1, "at+jwt"), 0);
		ck_assert_int_eq(jwt_checker_verify(c1, tok), 0);

		c2 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_expect_typ(c2, "AT+JWT"), 0);
		ck_assert_int_eq(jwt_checker_verify(c2, tok), 0);

		c3 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c3, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_expect_typ(c3, "application/at+jwt"), 0);
		ck_assert_int_eq(jwt_checker_verify(c3, tok), 0);

		/* A different typ is rejected. */
		c4 = jwt_checker_new();
		ck_assert_int_eq(jwt_checker_setkey(c4, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_expect_typ(c4, "dpop+jwt"), 0);
		ck_assert_int_ne(jwt_checker_verify(c4, tok), 0);

		jwt_freemem(tok);
		tok = NULL;
	}

	/* expect_typ when the token has no "typ" at all is rejected. */
	{
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *t = gen(ec, NULL, JWT_FORMAT_COMPACT);

		/* JWT default typ is "JWT"; expecting "at+jwt" must fail. */
		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_expect_typ(c, "at+jwt"), 0);
		ck_assert_int_ne(jwt_checker_verify(c, t), 0);
		/* Clearing the expectation accepts again. */
		ck_assert_int_eq(jwt_checker_expect_typ(c, NULL), 0);
		ck_assert_int_eq(jwt_checker_verify(c, t), 0);
	}

	jwks_free(ks);
}
END_TEST

START_TEST(test_allowlist)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	char_auto *tok = NULL, *none_tok = NULL;
	jwt_alg_t ok_set[] = { JWT_ALG_RS256, JWT_ALG_ES256 };
	jwt_alg_t no_set[] = { JWT_ALG_RS256, JWT_ALG_RS512 };
	jwt_builder_auto_t *nb = NULL;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL, *c3 = NULL;

	SET_OPS();
	ks = load_ec();
	ec = jwks_item_get(ks, 0);

	tok = gen(ec, NULL, JWT_FORMAT_COMPACT);
	ck_assert_ptr_nonnull(tok);

	/* ES256 is in the permitted set. */
	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c1, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c1, ok_set, 2), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, tok), 0);

	/* ES256 is NOT in this set -> rejected. */
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_setalgs(c2, no_set, 2), 0);
	ck_assert_int_ne(jwt_checker_verify(c2, tok), 0);
	/* Clearing the allowlist accepts again. */
	ck_assert_int_eq(jwt_checker_setalgs(c2, NULL, 0), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, tok), 0);

	/* An alg:none token is rejected by an allowlist that lacks none. */
	nb = jwt_builder_new();
	none_tok = jwt_builder_generate(nb);
	ck_assert_ptr_nonnull(none_tok);
	c3 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setalgs(c3, ok_set, 2), 0);
	ck_assert_int_ne(jwt_checker_verify(c3, none_tok), 0);

	jwks_free(ks);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_typ_alg");

	tcase_add_loop_test(tc_core, test_typ, 0, i);
	tcase_add_loop_test(tc_core, test_allowlist, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT typ helper + algorithm allowlist (#312)");
}
