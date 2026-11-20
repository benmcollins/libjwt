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

/* Load @json, a single JWK, and check that its one item is in error with
 * @msg and is not private. With @no_key, it also holds no key: it failed
 * before any backend loaded one (a key flagged after it loaded keeps its
 * size, though it is never used). */
static void check_item_error(const char *json, const char *msg, int no_key)
{
	jwk_set_auto_t *jwk_set = jwks_create(json);
	const jwk_item_t *item;

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert_int_eq(jwks_error(jwk_set), 0);
	ck_assert_int_eq(jwks_item_count(jwk_set), 1);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);
	ck_assert_str_eq(jwks_item_error_msg(item), msg);
	ck_assert_int_eq(jwks_item_is_private(item), 0);
	if (no_key)
		ck_assert_int_eq(jwks_item_key_bits(item), 0);
}

/* @rfc{7517,5.1} A "keys" member that is there but is not an array (a JSON
 * null too) fails the set, with both JSON backends. It used to give an empty
 * set without an error, or, for a null with json-c, read the document as one
 * JWK with no "kty". */
START_TEST(test_jwks_keys_not_array)
{
	static const char * const docs[] = {
		"{\"keys\":null}",
		"{\"keys\":\"not an array\"}",
		"{\"keys\":5}",
		"{\"keys\":{\"kty\":\"oct\",\"k\":\"AAAA\"}}",
	};
	size_t n;

	SET_OPS();

	for (n = 0; n < ARRAY_SIZE(docs); n++) {
		jwk_set_auto_t *jwk_set = jwks_create(docs[n]);

		ck_assert_ptr_nonnull(jwk_set);
		ck_assert_int_ne(jwks_error(jwk_set), 0);
		ck_assert_str_eq(jwks_error_msg(jwk_set),
				 "Invalid JWKS: \"keys\" is not an array");
		ck_assert_int_eq(jwks_item_count(jwk_set), 0);
	}
}
END_TEST

#define RSA_PUB	"\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":"				\
	"\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"	\
	"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"	\
	"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"	\
	"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"	\
	"FH6wAvvL6F_\""
#define EC_PUB	"\"kty\":\"EC\",\"crv\":\"P-256\","				\
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","		\
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\""
#define OKP_PUB	"\"kty\":\"OKP\",\"crv\":\"Ed25519\","				\
	"\"x\":\"HUj-14kN6N4i5qNVkfEhwKiCf-tSrvRHstQdtV8a5QM\""

/* A JSON null "alg" or "x5c" is present, with a value of the wrong type: the
 * key is in error, with both JSON backends (json-c used to read it as absent
 * and load the key). */
START_TEST(test_jwks_alg_x5c_null)
{
	SET_OPS();

	check_item_error("{" RSA_PUB ",\"alg\":null}", "Invalid alg type", 0);
	check_item_error("{" EC_PUB ",\"alg\":null}", "Invalid alg type", 0);
	check_item_error("{" RSA_PUB ",\"x5c\":null}",
			 "Invalid JWK: \"x5c\" is not an array", 0);
	check_item_error("{" OKP_PUB ",\"x5c\":null}",
			 "Invalid JWK: \"x5c\" is not an array", 0);
}
END_TEST

/* A private member that is there with a value that is not a string (a JSON
 * null too) puts the key in error with every JSON and crypto backend, before
 * any backend reads it. json-c used to read a null one as absent and load the
 * public key; with Jansson the crypto backends disagreed (OpenSSL failed the
 * key, GnuTLS loaded the public part of an EC or OKP key, and MbedTLS marked
 * such an OKP key private). */
START_TEST(test_jwks_priv_member_null)
{
	static const struct {
		const char *json;
		const char *member;
	} cases[] = {
		/* RSA: one member null, all six null, a later one null, and
		 * a number. */
		{ "{" RSA_PUB ",\"d\":null}", "d" },
		{ "{" RSA_PUB ",\"d\":null,\"p\":null,\"q\":null,"
		  "\"dp\":null,\"dq\":null,\"qi\":null}", "d" },
		{ "{" RSA_PUB ",\"d\":\"AQAB\",\"p\":\"AQAB\",\"q\":\"AQAB\","
		  "\"dp\":\"AQAB\",\"dq\":\"AQAB\",\"qi\":null}", "qi" },
		{ "{" RSA_PUB ",\"p\":12345678}", "p" },
		/* EC and OKP "d". */
		{ "{" EC_PUB ",\"d\":null}", "d" },
		{ "{" EC_PUB ",\"d\":123}", "d" },
		{ "{" OKP_PUB ",\"d\":null}", "d" },
		{ "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"d\":false}", "d" },
		/* AKP "priv", whether or not the build can load AKP keys. */
		{ "{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"AAAA\","
		  "\"priv\":null}", "priv" },
	};
	static const struct {
		const char *json;
		jwt_alg_t alg;
	} kid_cases[] = {
		{ "{" RSA_PUB ",\"kid\":\"k1\",\"alg\":\"RS256\",\"use\":\"sig\","
		  "\"d\":null}", JWT_ALG_RS256 },
		{ "{" EC_PUB ",\"kid\":\"k1\",\"alg\":\"ES256\",\"use\":\"sig\","
		  "\"d\":5}", JWT_ALG_ES256 },
		{ "{" OKP_PUB ",\"kid\":\"k1\",\"alg\":\"EdDSA\",\"use\":\"sig\","
		  "\"d\":null}", JWT_ALG_EDDSA },
		{ "{\"kty\":\"AKP\",\"kid\":\"k1\",\"alg\":\"HS256\","
		  "\"use\":\"sig\",\"pub\":\"AAAA\",\"priv\":null}",
		  JWT_ALG_HS256 },
	};
	size_t n;

	SET_OPS();

	for (n = 0; n < ARRAY_SIZE(cases); n++) {
		char msg[64];

		snprintf(msg, sizeof(msg), "Invalid JWK: \"%s\" is not a string",
			 cases[n].member);
		check_item_error(cases[n].json, msg, 1);
	}

	/* Only the backend is skipped: the key keeps its "kid" and "alg",
	 * as any other key that fails to load, so it can still be named. */
	for (n = 0; n < ARRAY_SIZE(kid_cases); n++) {
		jwk_set_auto_t *jwk_set = jwks_create(kid_cases[n].json);
		const jwk_item_t *item;

		ck_assert_ptr_nonnull(jwk_set);
		item = jwks_item_get(jwk_set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwks_item_error(item), 0);
		ck_assert_ptr_nonnull(jwks_item_kid(item));
		ck_assert_str_eq(jwks_item_kid(item), "k1");
		ck_assert_int_eq(jwks_item_alg(item), kid_cases[n].alg);
		ck_assert_int_eq(jwks_item_use(item), JWK_PUB_KEY_USE_SIG);
		ck_assert_ptr_eq(jwks_find_bykid(jwk_set, "k1"), item);
	}
}
END_TEST

/* A key member that is a string but not base64url, or that decodes to
 * nothing, puts the key in error (the message is the backend's own). */
START_TEST(test_jwks_member_undecodable)
{
	static const char * const docs[] = {
		"{" EC_PUB ",\"d\":\"\"}",
		"{" EC_PUB ",\"d\":\"***\"}",
		"{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"\"}",
		"{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"***\"}",
		"{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"\"}",
	};
	size_t n;

	SET_OPS();

	for (n = 0; n < ARRAY_SIZE(docs); n++) {
		jwk_set_auto_t *jwk_set = jwks_create(docs[n]);
		const jwk_item_t *item;

		ck_assert_ptr_nonnull(jwk_set);
		item = jwks_item_get(jwk_set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwks_item_error(item), 0);
		ck_assert_int_eq(jwks_item_is_private(item), 0);
		ck_assert_int_eq(jwks_item_key_bits(item), 0);
	}
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

	/* json-c behaves as Jansson does (JSON null members) */
	tcase_add_loop_test(tc_core, test_jwks_keys_not_array, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_alg_x5c_null, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_priv_member_null, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_member_undecodable, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS Error Path Testing");
}
