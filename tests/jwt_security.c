/* Public domain, no copyright. Use at your own risk. */

/* Security regression tests for libjwt.
 *
 * These tests validate fixes for security vulnerabilities including:
 * - Ill-structured JSON for JWT and JWKS parsing
 * - Malformed base64 inputs
 * - Missing or invalid header fields
 * - Type confusion in JWK fields
 * - Truncated and oversized tokens
 * - NULL and empty input handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

/*
 * === JWKS Ill-Structured JSON Tests ===
 *
 * These test malformed JWK/JWKS JSON documents to ensure the parser
 * handles them gracefully without crashes or undefined behavior.
 */

/* JWK with "alg" as a non-string type (integer) - tests alg_str NULL deref fix */
START_TEST(test_jwks_rsa_alg_integer)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"e\":\"AQAB\","
		"\"alg\":256}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	/* Should parse without crashing even though alg is not a string */
	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with "alg" as JSON null */
START_TEST(test_jwks_rsa_alg_null)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"e\":\"AQAB\","
		"\"alg\":null}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with "alg" as a boolean */
START_TEST(test_jwks_rsa_alg_boolean)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"e\":\"AQAB\","
		"\"alg\":true}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with "kty" as non-string type */
START_TEST(test_jwks_kty_integer)
{
	const char *json = "{\"kty\":123}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWKS with empty "keys" array */
START_TEST(test_jwks_empty_keys_array)
{
	const char *json = "{\"keys\":[]}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_null(item);

	jwks_free(jwk_set);
}
END_TEST

/* JWKS with "keys" as a string instead of array */
START_TEST(test_jwks_keys_not_array)
{
	const char *json = "{\"keys\":\"not an array\"}";
	jwk_set_t *jwk_set = NULL;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);
	/* Should handle gracefully */

	jwks_free(jwk_set);
}
END_TEST

/* JWK with missing required EC components */
START_TEST(test_jwks_ec_missing_x)
{
	const char *json = "{\"kty\":\"EC\","
		"\"crv\":\"P-256\","
		"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
		"\"alg\":\"ES256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with missing required EC curve */
START_TEST(test_jwks_ec_missing_crv)
{
	const char *json = "{\"kty\":\"EC\","
		"\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
		"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
		"\"alg\":\"ES256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with RSA missing 'n' component */
START_TEST(test_jwks_rsa_missing_n)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"e\":\"AQAB\","
		"\"alg\":\"RS256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with RSA missing 'e' component */
START_TEST(test_jwks_rsa_missing_e)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"alg\":\"RS256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* EdDSA JWK with missing 'x' (public key) */
START_TEST(test_jwks_eddsa_missing_x)
{
	const char *json = "{\"kty\":\"OKP\","
		"\"crv\":\"Ed25519\","
		"\"alg\":\"EdDSA\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* RSA JWK with partial private key (some but not all components) */
START_TEST(test_jwks_rsa_partial_private_key)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"e\":\"AQAB\","
		"\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxn\","
		"\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	/* Should detect missing q, dp, dq, qi */
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with values as wrong types (n as integer, e as array) */
START_TEST(test_jwks_rsa_wrong_value_types)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":12345,"
		"\"e\":[1,2,3],"
		"\"alg\":\"RS256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* Deeply nested JSON object */
START_TEST(test_jwks_deeply_nested)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":{\"a\":{\"b\":{\"c\":\"deep\"}}},"
		"\"e\":\"AQAB\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* Empty JSON object */
START_TEST(test_jwks_empty_object)
{
	const char *json = "{}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* Empty string as JWK */
START_TEST(test_jwks_empty_string)
{
	const char *json = "";
	jwk_set_t *jwk_set = NULL;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(jwks_error(jwk_set));

	jwks_free(jwk_set);
}
END_TEST

/* JSON array at top level (not object) */
START_TEST(test_jwks_top_level_array)
{
	const char *json = "[{\"kty\":\"RSA\",\"n\":\"abc\",\"e\":\"AQAB\"}]";
	jwk_set_t *jwk_set = NULL;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);
	/* Should not crash regardless of how it handles this */

	jwks_free(jwk_set);
}
END_TEST

/* JWKS with mixed valid and invalid keys */
START_TEST(test_jwks_mixed_valid_invalid)
{
	const char *json = "{\"keys\":["
		"{\"kty\":\"RSA\",\"n\":\"bad\"},"
		"{\"kty\":\"INVALID\"},"
		"{\"NOT-kty\":\"missing\"}"
		"]}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	int i;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	/* All items should have errors but none should crash */
	for (i = 0; (item = jwks_item_get(jwk_set, i)) != NULL; i++)
		ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* OCT key with invalid base64 in "k" */
START_TEST(test_jwks_oct_invalid_base64)
{
	const char *json = "{\"kty\":\"oct\","
		"\"k\":\"!!!not-valid-base64!!!\","
		"\"alg\":\"HS256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/* JWK with extra unexpected fields (should be ignored) */
START_TEST(test_jwks_extra_fields)
{
	const char *json = "{\"kty\":\"oct\","
		"\"k\":\"AyM32fcIOpOGAyXWTiHs\","
		"\"alg\":\"HS256\","
		"\"malicious_field\":\"should be ignored\","
		"\"x5c\":[\"not a cert\"],"
		"\"nested\":{\"deep\":true}}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	/* Key should parse; extra fields ignored */

	jwks_free(jwk_set);
}
END_TEST

/*
 * === JWT Parsing Security Tests ===
 *
 * These test malformed JWT token strings to ensure the parser
 * handles them gracefully.
 */

/* Token with no dots at all */
START_TEST(test_jwt_no_dots)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_verify(checker, "nodotshere");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with only one dot */
START_TEST(test_jwt_one_dot)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_verify(checker, "one.dot");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Empty token */
START_TEST(test_jwt_empty_token)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_verify(checker, "");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* NULL token */
START_TEST(test_jwt_null_token)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_verify(checker, NULL);
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with empty header (..payload.sig) */
START_TEST(test_jwt_empty_header)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* Empty string before first dot */
	ret = jwt_checker_verify(checker, ".eyJ0ZXN0IjoiMSJ9.");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with header that is valid base64 but not JSON */
START_TEST(test_jwt_header_not_json)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* "not json" in base64url = "bm90IGpzb24" */
	ret = jwt_checker_verify(checker, "bm90IGpzb24.eyJ0ZXN0IjoiMSJ9.");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with header missing alg field */
START_TEST(test_jwt_header_missing_alg)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;
	const char *msg;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* {"typ":"JWT"} in base64url (no alg field) */
	ret = jwt_checker_verify(checker,
		"eyJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiMSJ9.");
	ck_assert_int_ne(ret, 0);

	msg = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(msg);
	ck_assert(strlen(msg) > 0);
}
END_TEST

/* Token with invalid alg value */
START_TEST(test_jwt_header_invalid_alg)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* {"alg":"BOGUS"} in base64url */
	ret = jwt_checker_verify(checker,
		"eyJhbGciOiJCT0dVUyJ9.eyJ0ZXN0IjoiMSJ9.");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with alg as integer in header */
START_TEST(test_jwt_header_alg_integer)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;
	const char *msg;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* {"alg":256} in base64url */
	ret = jwt_checker_verify(checker,
		"eyJhbGciOjI1Nn0.eyJ0ZXN0IjoiMSJ9.");
	ck_assert_int_ne(ret, 0);

	msg = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(msg);
	ck_assert(strlen(msg) > 0);
}
END_TEST

/* Token with many dots */
START_TEST(test_jwt_many_dots)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_verify(checker, "a.b.c.d.e.f");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with invalid base64 in payload */
START_TEST(test_jwt_invalid_base64_payload)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* Valid header {"alg":"none"}, garbage payload, empty sig */
	ret = jwt_checker_verify(checker,
		"eyJhbGciOiJub25lIn0.!!!invalid!!!.");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Token with empty payload and empty signature (alg:none) */
START_TEST(test_jwt_alg_none_empty)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	/* {"alg":"none"} . {} . (empty sig) */
	ret = jwt_checker_verify(checker,
		"eyJhbGciOiJub25lIn0.e30.");
	ck_assert_int_eq(ret, 0);
}
END_TEST

/*
 * === JWKS load_strn boundary tests ===
 */

/* Zero length string to jwks_load_strn */
START_TEST(test_jwks_load_strn_zero_len)
{
	jwk_set_t *jwk_set = NULL;

	SET_OPS();

	jwk_set = jwks_create_strn("{}", 0);
	ck_assert_ptr_nonnull(jwk_set);

	jwks_free(jwk_set);
}
END_TEST

/* Truncated JSON to jwks_load_strn */
START_TEST(test_jwks_load_strn_truncated)
{
	const char *json = "{\"kty\":\"RSA\",\"n\":\"abc\",\"e\":\"AQAB\"}";
	jwk_set_t *jwk_set = NULL;

	SET_OPS();

	/* Pass only half the string */
	jwk_set = jwks_create_strn(json, 10);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(jwks_error(jwk_set));

	jwks_free(jwk_set);
}
END_TEST

/*
 * === JWKS NULL and edge case handling ===
 */

/* Multiple operations on NULL jwk_set */
START_TEST(test_jwks_null_operations)
{
	SET_OPS();

	/* These are documented as NULL-safe and must not crash */
	ck_assert_ptr_null(jwks_item_get(NULL, 0));
	ck_assert_int_eq(jwks_item_free(NULL, 0), 0);
	ck_assert_int_eq(jwks_item_free_all(NULL), 0);
	jwks_free(NULL);

	ck_assert_ptr_null(jwks_create_strn(NULL, 0));
	ck_assert_ptr_null(jwks_create_fromfile(NULL));
	ck_assert_ptr_null(jwks_create_fromfp(NULL));
}
END_TEST

/* Checker NULL safety */
START_TEST(test_checker_null_safety)
{
	int ret;
	const char *msg;

	SET_OPS();

	jwt_checker_free(NULL);

	ret = jwt_checker_error(NULL);
	ck_assert_int_ne(ret, 0);

	msg = jwt_checker_error_msg(NULL);
	ck_assert_ptr_null(msg);

	ret = jwt_checker_setkey(NULL, JWT_ALG_NONE, NULL);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_verify(NULL, "test");
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* Builder NULL safety */
START_TEST(test_builder_null_safety)
{
	char *out;
	int ret;
	const char *msg;

	SET_OPS();

	jwt_builder_free(NULL);

	ret = jwt_builder_error(NULL);
	ck_assert_int_ne(ret, 0);

	msg = jwt_builder_error_msg(NULL);
	ck_assert_ptr_null(msg);

	ret = jwt_builder_setkey(NULL, JWT_ALG_NONE, NULL);
	ck_assert_int_ne(ret, 0);

	out = jwt_builder_generate(NULL);
	ck_assert_ptr_null(out);
}
END_TEST

/*
 * === JWK with PSS alg sniffing ===
 *
 * Tests the alg_str dereference fix specifically.
 */
START_TEST(test_jwks_rsa_pss_alg_string)
{
	const char *json = "{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
		"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
		"Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
		"s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQ"
		"FH6wAvvL6F_\","
		"\"e\":\"AQAB\","
		"\"alg\":\"PS256\"}";
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;

	SET_OPS();

	jwk_set = jwks_create(json);
	ck_assert_ptr_nonnull(jwk_set);

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	/* Should parse successfully with PS256 */
	ck_assert_int_eq(jwks_item_error(item), 0);

	jwks_free(jwk_set);
}
END_TEST

/*
 * === Algorithm Confusion Regression (GHSA-q843-6q5f-w55g) ===
 *
 * An RSA JWK with no "alg" hint must not be usable for any HMAC
 * algorithm. Without the fix, libjwt would accept the RSA JWK for
 * HS256/384/512 and run HMAC against a zero-length key
 * (oct.key/oct.len read from the union shared with provider_data).
 * That allowed an attacker who only knows the public JWKS to forge
 * tokens that verify successfully.
 */

/* The exact PoC from the advisory: RSA public JWK without "alg",
 * verifying an HS256 token whose signature is HMAC-SHA256("", header.payload).
 * Must be rejected before the HMAC ever runs. */
START_TEST(test_alg_confusion_rsa_no_alg_hs256)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub_no_alg.json");

	/* The setkey call itself must reject the kty/alg mismatch. */
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* Same defense for HS384 and HS512. */
START_TEST(test_alg_confusion_rsa_no_alg_hs384)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub_no_alg.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS384, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

START_TEST(test_alg_confusion_rsa_no_alg_hs512)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub_no_alg.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS512, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* RSA JWK that DOES carry an "alg" hint of RS256 must still be rejected
 * for HS256: the prior code allowed it whenever the JWK alg matched the
 * caller alg, but here the kty would still be RSA. We assert the broader
 * invariant: HS* requires kty=oct period. */
START_TEST(test_alg_confusion_rsa_with_alg_hs256)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* EC JWK must not be usable for an HMAC algorithm either. */
START_TEST(test_alg_confusion_ec_hs256)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("ec_key_prime256v1_pub.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* OKP/EdDSA JWK must not be usable for an HMAC algorithm either. */
START_TEST(test_alg_confusion_okp_hs256)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("eddsa_key_ed25519_pub.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* The realistic application pattern: a JWKS callback that picks a key
 * by "kid" and copies the JWT header alg into config->alg. The attacker
 * controls the header alg. With the fix, the verify path's __setkey_check
 * (run after the callback) rejects the kty/alg mismatch. */
static int alg_confusion_cb(jwt_t *jwt, jwt_config_t *config)
{
	/* g_item is the RSA-no-alg JWK loaded by the test. */
	config->key = g_item;
	config->alg = jwt_get_alg(jwt);
	return 0;
}

START_TEST(test_alg_confusion_callback_rsa_no_alg)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] =
		"eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYS1uby1hbGcifQ"
		".eyJzdWIiOiJhZG1pbiJ9"
		".I2Ey63EMS9lOFEL93tQM8eB8cCnH6QJy0rIe1HVEI3I";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub_no_alg.json");

	ret = jwt_checker_setcb(checker, alg_confusion_cb, NULL);
	ck_assert_int_eq(ret, 0);

	/* The forged token must NOT verify. */
	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* Defense in depth: a malformed JWK whose "alg" hint disagrees with its
 * "kty" (here kty=RSA, alg=HS256) must not be usable for HMAC. The caller
 * sets alg=NONE so __setkey_check defers to the JWK's alg hint, but the
 * verify path then double-checks kty against the bound algorithm. */
START_TEST(test_alg_confusion_malformed_jwk_kty_alg)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] =
		"eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYS1uby1hbGcifQ"
		".eyJzdWIiOiJhZG1pbiJ9"
		".I2Ey63EMS9lOFEL93tQM8eB8cCnH6QJy0rIe1HVEI3I";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub_alg_hs256.json");

	/* alg=NONE: caller trusts whatever the JWK says. The JWK lies
	 * (kty=RSA, alg=HS256). __setkey_check accepts because alg=NONE,
	 * but the verify path's defensive kty switch must reject. */
	ret = jwt_checker_setkey(checker, JWT_ALG_NONE, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match JWT alg");

	free_key();
}
END_TEST

/*
 * === Suite Setup ===
 */

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_jwks_json;
	TCase *tc_jwt_parse;
	TCase *tc_null_safety;
	TCase *tc_alg_confusion;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	/* JWKS ill-structured JSON tests */
	tc_jwks_json = tcase_create("jwks_malformed_json");

	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_alg_integer, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_alg_null, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_alg_boolean, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_kty_integer, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_empty_keys_array, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_keys_not_array, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_ec_missing_x, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_ec_missing_crv, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_missing_n, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_missing_e, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_eddsa_missing_x, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_partial_private_key, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_wrong_value_types, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_deeply_nested, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_empty_object, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_empty_string, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_top_level_array, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_mixed_valid_invalid, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_oct_invalid_base64, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_extra_fields, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_rsa_pss_alg_string, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_load_strn_zero_len, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_load_strn_truncated, 0, i);

	tcase_set_timeout(tc_jwks_json, 30);
	suite_add_tcase(s, tc_jwks_json);

	/* JWT token parsing tests */
	tc_jwt_parse = tcase_create("jwt_malformed_tokens");

	tcase_add_loop_test(tc_jwt_parse, test_jwt_no_dots, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_one_dot, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_empty_token, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_null_token, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_empty_header, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_header_not_json, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_header_missing_alg, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_header_invalid_alg, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_header_alg_integer, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_many_dots, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_invalid_base64_payload, 0, i);
	tcase_add_loop_test(tc_jwt_parse, test_jwt_alg_none_empty, 0, i);

	tcase_set_timeout(tc_jwt_parse, 30);
	suite_add_tcase(s, tc_jwt_parse);

	/* NULL safety tests */
	tc_null_safety = tcase_create("null_safety");

	tcase_add_loop_test(tc_null_safety, test_jwks_null_operations, 0, i);
	tcase_add_loop_test(tc_null_safety, test_checker_null_safety, 0, i);
	tcase_add_loop_test(tc_null_safety, test_builder_null_safety, 0, i);

	tcase_set_timeout(tc_null_safety, 30);
	suite_add_tcase(s, tc_null_safety);

	/* Algorithm confusion regression (GHSA-q843-6q5f-w55g) */
	tc_alg_confusion = tcase_create("alg_confusion");

	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_rsa_no_alg_hs256, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_rsa_no_alg_hs384, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_rsa_no_alg_hs512, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_rsa_with_alg_hs256, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_ec_hs256, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_okp_hs256, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_callback_rsa_no_alg, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_alg_confusion_malformed_jwk_kty_alg, 0, i);

	tcase_set_timeout(tc_alg_confusion, 30);
	suite_add_tcase(s, tc_alg_confusion);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Security Regression Tests");
}
