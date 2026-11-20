/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "jwt_tests.h"

/* jwt_checker_setmaxsize() (#378): a checker rejects a token longer than its
 * maximum size (1 MiB by default) with "Token too large" before parsing it,
 * in jwt_checker_verify() and jwt_checker_verify_detached() alike. Runs
 * under each compiled crypto backend and both JSON backends. */

#define MIB		((size_t)1024 * 1024)
#define TOO_LARGE	"Token too large"

/* The largest single allocation made through the jwt allocator while
 * track_malloc() is installed. */
static size_t g_max_alloc;

static void *track_malloc(size_t size)
{
	if (size > g_max_alloc)
		g_max_alloc = size;

	return malloc(size);
}

static jwk_set_t *load_key(void)
{
	jwk_set_t *set = jwks_create_fromfile(KEYDIR "/oct_key_256.json");

	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);

	return set;
}

/* A JSON object payload of exactly @len bytes: {"p":"aaa...a"}. */
static unsigned char *make_payload(size_t len)
{
	unsigned char *p;

	ck_assert_uint_ge(len, 9);
	p = malloc(len);
	ck_assert_ptr_nonnull(p);
	memcpy(p, "{\"p\":\"", 6);
	memset(p + 6, 'a', len - 8);
	memcpy(p + len - 2, "\"}", 2);

	return p;
}

/* An HS256 token over a @len byte payload, in @format, optionally with the
 * payload detached. */
static char *make_token(const jwk_item_t *key, jwt_serialization_t format,
			int detached, size_t len)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	unsigned char *p = make_payload(len);
	char *tok;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_HS256, key), 0);
	ck_assert_int_eq(jwt_builder_setpayload(b, p, len), 0);
	ck_assert_int_eq(jwt_builder_set_format(b, format), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, detached), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);
	free(p);

	return tok;
}

static jwt_checker_t *new_checker(const jwk_item_t *key)
{
	jwt_checker_t *c = jwt_checker_new();

	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256, key), 0);

	return c;
}

static void assert_too_large(jwt_checker_t *c, int ret)
{
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), TOO_LARGE);
}

/* @tok preceded by enough spaces to make it exactly @total bytes. A JWS JSON
 * Serialization may carry leading whitespace, and it counts toward the
 * limit, so this lands a token that verifies on any exact length. */
static char *pad_to(const char *tok, size_t total)
{
	size_t len = strlen(tok);
	char *out;

	ck_assert_uint_le(len, total);
	out = malloc(total + 1);
	ck_assert_ptr_nonnull(out);
	memset(out, ' ', total - len);
	memcpy(out + total - len, tok, len + 1);
	ck_assert_uint_eq(strlen(out), total);

	return out;
}

/* The default limit is 1 MiB: a token of exactly 1048576 bytes verifies and
 * one byte more is refused before it is parsed. */
START_TEST(test_maxsize_default_boundary)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL, *at = NULL, *over = NULL;
	char *junk;
	jwk_set_t *ks;
	const jwk_item_t *key;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);
	c = new_checker(key);

	tok = make_token(key, JWT_FORMAT_JSON_FLAT, 0, 700000);
	ck_assert_uint_lt(strlen(tok), MIB);

	at = pad_to(tok, MIB);
	ck_assert_int_eq(jwt_checker_verify(c, at), 0);
	ck_assert_int_eq(jwt_checker_error(c), 0);

	over = pad_to(tok, MIB + 1);
	assert_too_large(c, jwt_checker_verify(c, over));

	/* Size alone decides: 1 MiB of junk gets as far as the parser (and
	 * fails there), 1 MiB + 1 does not. */
	junk = malloc(MIB + 2);
	ck_assert_ptr_nonnull(junk);
	memset(junk, 'a', MIB + 1);
	junk[MIB + 1] = '\0';
	assert_too_large(c, jwt_checker_verify(c, junk));
	junk[MIB] = '\0';
	ck_assert_int_ne(jwt_checker_verify(c, junk), 0);
	ck_assert_str_ne(jwt_checker_error_msg(c), TOO_LARGE);
	free(junk);

	jwks_free(ks);
}
END_TEST

/* The setter takes 1 to INT_MAX - 1 and refuses anything else, keeping the
 * limit it had. */
START_TEST(test_maxsize_setter_bounds)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;
	size_t len;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);
	c = new_checker(key);

	ck_assert_int_ne(jwt_checker_setmaxsize(NULL, 100), 0);

	tok = make_token(key, JWT_FORMAT_COMPACT, 0, 100);
	len = strlen(tok);

	/* Set it to the token's length exactly, then refuse bad values. */
	ck_assert_int_eq(jwt_checker_setmaxsize(c, len), 0);
	ck_assert_int_eq(jwt_checker_error(c), 0);

	ck_assert_int_ne(jwt_checker_setmaxsize(c, 0), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c),
			 "Invalid maximum token size");
	jwt_checker_error_clear(c);

	ck_assert_int_ne(jwt_checker_setmaxsize(c, (size_t)INT_MAX), 0);
	jwt_checker_error_clear(c);
	ck_assert_int_ne(jwt_checker_setmaxsize(c, SIZE_MAX), 0);

	/* Still the token's length: it verifies, one byte less does not. */
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	ck_assert_int_eq(jwt_checker_setmaxsize(c, len - 1), 0);
	assert_too_large(c, jwt_checker_verify(c, tok));

	/* The ceiling itself is accepted. */
	ck_assert_int_eq(jwt_checker_setmaxsize(c, (size_t)INT_MAX - 1), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

	/* The smallest limit still sees an empty token as no token. */
	ck_assert_int_eq(jwt_checker_setmaxsize(c, 1), 0);
	ck_assert_int_ne(jwt_checker_verify(c, ""), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), "Must pass a token");
	assert_too_large(c, jwt_checker_verify(c, "ab"));

	jwks_free(ks);
}
END_TEST

/* A raised limit admits a 2 MiB token (Compact and JSON) that the default
 * refuses. */
START_TEST(test_maxsize_raised)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *compact = NULL, *json = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);
	c = new_checker(key);

	/* 1.5 MiB of payload is 2 MiB once base64url-encoded. */
	compact = make_token(key, JWT_FORMAT_COMPACT, 0, 3 * MIB / 2);
	json = make_token(key, JWT_FORMAT_JSON_GENERAL, 0, 3 * MIB / 2);
	ck_assert_uint_gt(strlen(compact), 2 * MIB);
	ck_assert_uint_gt(strlen(json), 2 * MIB);

	assert_too_large(c, jwt_checker_verify(c, compact));
	assert_too_large(c, jwt_checker_verify(c, json));

	ck_assert_int_eq(jwt_checker_setmaxsize(c, 4 * MIB), 0);
	ck_assert_int_eq(jwt_checker_verify(c, compact), 0);
	ck_assert_int_eq(jwt_checker_verify(c, json), 0);
	ck_assert_int_eq(jwt_checker_sig_count(c), 1);

	jwks_free(ks);
}
END_TEST

/* A lowered limit refuses an ordinary token, Compact and JSON alike. */
START_TEST(test_maxsize_lowered)
{
	jwt_checker_auto_t *c = NULL;
	char_auto *compact = NULL, *json = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);
	c = new_checker(key);

	compact = make_token(key, JWT_FORMAT_COMPACT, 0, 2000);
	json = make_token(key, JWT_FORMAT_JSON_FLAT, 0, 2000);
	ck_assert_int_eq(jwt_checker_verify(c, compact), 0);
	ck_assert_int_eq(jwt_checker_verify(c, json), 0);

	ck_assert_int_eq(jwt_checker_setmaxsize(c, 1024), 0);
	assert_too_large(c, jwt_checker_verify(c, compact));
	assert_too_large(c, jwt_checker_verify(c, json));
	ck_assert_int_eq(jwt_checker_sig_count(c), 0);

	jwks_free(ks);
}
END_TEST

/* jwt_checker_verify_detached(): the detached token, the payload, and the
 * token rebuilt with the payload attached are all held to the limit. */
START_TEST(test_maxsize_detached)
{
	jwt_checker_auto_t *c = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;
	jwt_serialization_t fmts[] = {
		JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT,
	};
	size_t f;
	int ret;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(fmts); f++) {
		/* 900000 bytes fit the limit, but not once base64url-encoded
		 * (1200000); 1.5 MiB does not fit even raw. */
		const size_t mid = 900000, big = 3 * MIB / 2;
		unsigned char *pmid = make_payload(mid);
		unsigned char *pbig = make_payload(big);
		unsigned char *psmall = make_payload(64);
		char_auto *tmid = make_token(key, fmts[f], 1, mid);
		char_auto *tbig = make_token(key, fmts[f], 1, big);
		char_auto *tsmall = make_token(key, fmts[f], 1, 64);

		c = new_checker(key);

		/* The detached token is small; the default limit admits a
		 * small payload with it. */
		ck_assert_uint_lt(strlen(tmid), 1024);
		ck_assert_int_eq(jwt_checker_verify_detached(c, tsmall,
							     psmall, 64), 0);

		/* Within the limit raw, over it once attached. */
		assert_too_large(c, jwt_checker_verify_detached(c, tmid,
								pmid, mid));
		/* Over the limit on its own: refused before the payload is
		 * encoded, so nothing near its size is ever allocated (the
		 * base64url form alone would be 2 MiB). */
		g_max_alloc = 0;
		ck_assert_int_eq(jwt_set_alloc(track_malloc, NULL), 0);
		ret = jwt_checker_verify_detached(c, tbig, pbig, big);
		jwt_set_alloc(NULL, NULL);
		assert_too_large(c, ret);
		ck_assert_uint_lt(g_max_alloc, big);

		/* Raised, both verify. */
		ck_assert_int_eq(jwt_checker_setmaxsize(c, 4 * MIB), 0);
		ck_assert_int_eq(jwt_checker_verify_detached(c, tmid,
							     pmid, mid), 0);
		ck_assert_int_eq(jwt_checker_verify_detached(c, tbig,
							     pbig, big), 0);

		/* Lowered below the detached token itself. */
		ck_assert_int_eq(jwt_checker_setmaxsize(c, 16), 0);
		assert_too_large(c, jwt_checker_verify_detached(c, tsmall,
								psmall, 0));

		jwt_checker_free(c);
		c = NULL;
		free(pmid);
		free(pbig);
		free(psmall);
	}

	jwks_free(ks);
}
END_TEST

/* The limit belongs to the checker: a new one starts at the default. */
START_TEST(test_maxsize_new_checker)
{
	jwt_checker_t *c;
	char_auto *tok = NULL, *at = NULL, *over = NULL, *small = NULL;
	jwk_set_t *ks;
	const jwk_item_t *key;

	SET_OPS();
	ks = load_key();
	key = jwks_item_get(ks, 0);

	small = make_token(key, JWT_FORMAT_COMPACT, 0, 64);
	tok = make_token(key, JWT_FORMAT_JSON_FLAT, 0, 700000);
	at = pad_to(tok, MIB);
	over = pad_to(tok, MIB + 1);

	c = new_checker(key);
	ck_assert_int_eq(jwt_checker_setmaxsize(c, 16), 0);
	assert_too_large(c, jwt_checker_verify(c, small));
	jwt_checker_free(c);

	c = new_checker(key);
	ck_assert_int_eq(jwt_checker_verify(c, small), 0);
	ck_assert_int_eq(jwt_checker_verify(c, at), 0);
	assert_too_large(c, jwt_checker_verify(c, over));
	jwt_checker_free(c);

	c = new_checker(key);
	ck_assert_int_eq(jwt_checker_setmaxsize(c, 2 * MIB), 0);
	ck_assert_int_eq(jwt_checker_verify(c, over), 0);
	jwt_checker_free(c);

	c = new_checker(key);
	assert_too_large(c, jwt_checker_verify(c, over));
	jwt_checker_free(c);

	jwks_free(ks);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_maxsize");

	tcase_add_loop_test(tc_core, test_maxsize_default_boundary, 0, i);
	tcase_add_loop_test(tc_core, test_maxsize_setter_bounds, 0, i);
	tcase_add_loop_test(tc_core, test_maxsize_raised, 0, i);
	tcase_add_loop_test(tc_core, test_maxsize_lowered, 0, i);
	tcase_add_loop_test(tc_core, test_maxsize_detached, 0, i);
	tcase_add_loop_test(tc_core, test_maxsize_new_checker, 0, i);

	tcase_set_timeout(tc_core, 120);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT checker maximum token size (#378)");
}
