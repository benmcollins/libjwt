/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwks_bad_json)
{
	const char *json = "INVALID";
	jwk_set_t *jwk_set = NULL;
	const char *msg;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(jwks_error(jwk_set));

	msg = jwks_error_msg(jwk_set);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(msg[0] != '\0');

	jwks_free(jwk_set);
}
END_TEST

/*
 * Load @json, which does not parse, with jwks_create() and with
 * jwks_create_strn(). The set reports the error as "<source>: <text>", where
 * the text says what is wrong without repeating the input: it has none of the
 * characters in @chars, which only the input has. Under Jansson the message
 * is exactly @jansson_msg; json-c has fixed descriptions of its own.
 */
static void check_parse_error(const char *json, const char *chars,
			      const char *jansson_msg)
{
	int n;

	for (n = 0; n < 2; n++) {
		jwk_set_auto_t *jwk_set = NULL;
		const char *msg, *text;

		if (n == 0)
			jwk_set = jwks_create(json);
		else
			jwk_set = jwks_create_strn(json, strlen(json));

		ck_assert_ptr_nonnull(jwk_set);
		ck_assert_int_ne(jwks_error(jwk_set), 0);

		msg = jwks_error_msg(jwk_set);
		ck_assert_ptr_nonnull(msg);

		/* Some text after the source, with no space left at the end */
		text = strstr(msg, ": ");
		ck_assert_ptr_nonnull(text);
		ck_assert_int_ne(text[2], '\0');
		ck_assert_int_ne(msg[strlen(msg) - 1], ' ');

		ck_assert_msg(strpbrk(msg, chars) == NULL,
			      "\"%s\" has one of \"%s\"", msg, chars);

#ifdef HAVE_JSON_C
		(void)jansson_msg;
#else
		ck_assert_str_eq(msg, jansson_msg);
#endif
	}
}

/* A word that is not true, false or null */
START_TEST(test_jwks_parse_error_bare_word)
{
	SET_OPS();

	check_parse_error("[QWZKY]", "QWZKY", "<buffer>: invalid token");
}
END_TEST

/* A control character inside a string. Both backends refuse it on the control
 * character itself now (json-c via libjwt's pre-parse scan, which no longer
 * lets the lenient tokener keep the string and report the following missing
 * comma). The second string has " near '" in it, so Jansson's cut has to be at
 * the first one, where its own ending starts. */
START_TEST(test_jwks_parse_error_control_char)
{
	SET_OPS();

	check_parse_error("[\"QWZKY\x01\" 1]", "QWZKY",
			  "<buffer>: control character 0x1");
	check_parse_error("[\"Q near 'W\x01\" 1]", "QW",
			  "<buffer>: control character 0x1");
}
END_TEST

/* A Unicode escape whose fourth character is not a hex digit */
START_TEST(test_jwks_parse_error_bad_escape)
{
	SET_OPS();

	check_parse_error("[\"\\uFEDQ\"]", "FEDQ",
			  "<buffer>: invalid escape");
}
END_TEST

/* Unpaired surrogates: a high one at the end of the string, a low one on its
 * own, and a high one followed by a Unicode escape that is not a low one.
 * json-c puts U+FFFD in their place, so the comma after the string is left
 * out too, for json-c to report. Past 20 bytes of string, Jansson leaves out
 * the " near" ending, so in the last one only the "invalid Unicode" rule
 * takes the escape out. */
START_TEST(test_jwks_parse_error_surrogate)
{
	SET_OPS();

	check_parse_error("[\"\\uDBFE\" 1]", "BDEF",
			  "<buffer>: invalid Unicode");
	check_parse_error("[\"\\uDCBA\" 1]", "ABCD",
			  "<buffer>: invalid Unicode");
	check_parse_error("[\"\\uDBFE\\uABCD\" 1]", "ABCDEF",
			  "<buffer>: invalid Unicode");
	check_parse_error("[\"QWZKYQWZKYQWZKYQWZKY\\uDBFE\" 1]",
			  "BDEFKQWYZ", "<buffer>: invalid Unicode");
}
END_TEST

/* Input that ends early. Jansson's own quotes and its "near end of file" stay
 * in the message: they repeat nothing from the input. */
START_TEST(test_jwks_parse_error_end_of_input)
{
	SET_OPS();

	check_parse_error("[1, 2", "12",
			  "<buffer>: ']' expected near end of file");
}
END_TEST

/* An object key that is not a string. Jansson's own quotes stay in the
 * message; only the " near" ending, which repeats the input, goes. */
START_TEST(test_jwks_parse_error_object_key)
{
	SET_OPS();

	check_parse_error("{QWZKY}", "QWZKY",
			  "<buffer>: string or '}' expected");
}
END_TEST

/* A file that cannot be opened, in a directory whose name has " near '" in
 * it. Jansson names the path and the reason, with no " near" ending, and
 * the message stays whole. */
START_TEST(test_jwks_missing_file)
{
	const char path[] = "/nonexistent/a near 'QWZKY'/x.json";
	jwk_set_auto_t *jwk_set = NULL;
	char exp[256];

	SET_OPS();

	jwk_set = jwks_create_fromfile(path);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert_int_ne(jwks_error(jwk_set), 0);

#ifdef HAVE_JSON_C
	snprintf(exp, sizeof(exp), "%s: Unable to open file", path);
#else
	snprintf(exp, sizeof(exp), "%s: unable to open %s: %s", path, path,
		 strerror(ENOENT));
#endif
	ck_assert_str_eq(jwks_error_msg(jwk_set), exp);
}
END_TEST

START_TEST(test_jwks_unknown_kty)
{
	const char *json = "{\"kty\":\"INVALID\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Unknown or unsupported kty type";
	int ret;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ret = strncmp(exp, jwks_item_error_msg(item), strlen(exp));
	ck_assert_int_eq(ret, 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_missing_kty)
{
	const char *json = "{\"NOT-kty\":\"INVALID\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	const char exp[] = "Invalid JWK: missing kty value";
	int ret;

	SET_OPS();

	jwk_set = jwks_create(json);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	ret = strncmp(exp, jwks_item_error_msg(item), strlen(exp));
	ck_assert_int_eq(ret, 0);

	jwks_free(jwk_set);
}
END_TEST

START_TEST(test_jwks_empty)
{
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	int ret;

	SET_OPS();

	jwk_set = jwks_create(NULL);

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_null(item);

	/* Try some null things */
	ret = jwks_item_free(NULL, 0);
	ck_assert_int_eq(ret, 0);

	ret = jwks_item_free_all(NULL);
	ck_assert_int_eq(ret, 0);

	jwks_free(NULL);

	ck_assert_ptr_null(jwks_create_strn(NULL, 0));

	ck_assert_ptr_null(jwks_create_fromfile(NULL));

	ck_assert_ptr_null(jwks_create_fromfp(NULL));

	jwks_free(jwk_set);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_errors");

	/* Core JWKS Error path tests */
	tcase_add_loop_test(tc_core, test_jwks_bad_json, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_bare_word, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_control_char, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_bad_escape, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_surrogate, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_end_of_input, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_parse_error_object_key, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_missing_file, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_empty, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_unknown_kty, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_missing_kty, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing");
}
