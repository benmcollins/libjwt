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
#include <unistd.h>

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

/* OKP X25519 JWK with an oversized "x" (33 bytes instead of 32). The MbedTLS
 * backend previously imported the raw little-endian value with no length check,
 * accepting a malformed key that OpenSSL and GnuTLS reject. All backends must
 * now reject it (the field width is fixed at 32 bytes for X25519). */
START_TEST(test_jwks_okp_x25519_bad_x_len)
{
	const char *json = "{\"kty\":\"OKP\","
		"\"crv\":\"X25519\","
		/* 33-byte x (valid 32-byte value with a trailing zero byte). */
		"\"x\":\"S46Jc4ib5np5zMd8F4xCJL3wLqM_mYlgGGhw0XQAsBUA\"}";
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

/* As above but for the private scalar "d": a valid 32-byte X25519 "x" with an
 * oversized 33-byte "d" must also be rejected by the length check. */
START_TEST(test_jwks_okp_x25519_bad_d_len)
{
	const char *json = "{\"kty\":\"OKP\","
		"\"crv\":\"X25519\","
		"\"x\":\"S46Jc4ib5np5zMd8F4xCJL3wLqM_mYlgGGhw0XQAsBU\","
		"\"d\":\"8HS-8uSD0zo8pLVHOs3UQh6R57knGnjMgf7iCCknPGsA\"}";
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

/* A token with alg=RS256 but a signature segment far shorter than the RSA
 * modulus must be rejected, not read past the end of the heap-allocated
 * signature buffer. The MbedTLS RSA verify functions take no length argument
 * and read mbedtls_rsa_get_len() bytes unconditionally; without an explicit
 * size check the 3-byte signature here (base64url "AAAA") caused an ~253-byte
 * out-of-bounds heap read on the MbedTLS backend. All backends must reject it.
 */
START_TEST(test_rsa_short_signature_oob)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] =
		"eyJhbGciOiJSUzI1NiJ9"
		".eyJzdWIiOiJhZG1pbiJ9"
		".AAAA";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("rsa_key_2048_pub.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_RS256, g_item);
	ck_assert_int_eq(ret, 0);

	/* Must be rejected on every backend, and must not over-read. */
	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);

	free_key();
}

/* An out-of-range "exp" must not be silently accepted. json-c reports an
 * integer larger than INT64_MAX as a normal integer and clamps it to
 * INT64_MAX, which would make exp=99999999999999999999999999 verify as an
 * effectively never-expiring token; Jansson rejects the whole token at parse.
 * Both backends must reject the token (fail closed), and a valid far-future
 * exp must still verify. Both tokens below are HS256-signed with the
 * oct_key_256.json key. */
START_TEST(test_exp_out_of_range_int)
{
	jwt_checker_auto_t *checker = NULL;
	/* {"alg":"HS256"} . {"exp":99999999999999999999999999} . <hmac> */
	const char tok_big[] =
		"eyJhbGciOiJIUzI1NiJ9"
		".eyJleHAiOjk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5fQ"
		".LSbPILA_I3R_0saPbagko0aSRck-ZX9XZeRIduLgbvU";
	/* {"alg":"HS256"} . {"exp":7999999999} . <hmac> (valid, far future) */
	const char tok_ok[] =
		"eyJhbGciOiJIUzI1NiJ9"
		".eyJleHAiOjc5OTk5OTk5OTl9"
		".IFlzCWYGNIBrNj3BL5lOsS4baJqdmWc-7LVIfaKf5mw";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("oct_key_256.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	/* Out-of-range exp: rejected on both JSON backends. */
	ret = jwt_checker_verify(checker, tok_big);
	ck_assert_int_ne(ret, 0);
	jwt_checker_error_clear(checker);

	/* Control: a valid far-future exp still verifies. */
	ret = jwt_checker_verify(checker, tok_ok);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

/* Fault-injecting allocator: returns NULL on the Nth allocation. Used to
 * drive the out-of-memory error paths in JWKS parsing deterministically. */
static long g_alloc_fail_at = -1;
static long g_alloc_count;

static void *failing_malloc(size_t size)
{
	if (++g_alloc_count == g_alloc_fail_at)
		return NULL;
	return malloc(size);
}

static void failing_free(void *ptr)
{
	free(ptr);
}

/* Smoke test for the JWKS allocation-failure paths: parse a multi-key JWKS
 * while failing each successive allocation in turn, and assert the library
 * never crashes and teardown is clean.
 *
 * This exercises (under the Jansson backend, whose allocator this hook can
 * override) the out-of-memory branches in jwk_process_one(), including the
 * clone-failure path whose deallocator bug this change fixes. It is a
 * robustness guard rather than a discriminating reproducer: the wrong-free
 * corrupted a borrowed, refcounted JSON node, which json's refcounting does
 * not surface as a deterministic fault here, and the json-c allocator hook is
 * a no-op so that backend's internal clone cannot be failed this way. The
 * actual fix (free the owned jwk_item_t, never the borrowed argument) is
 * verified by inspection; this test ensures the OOM paths stay crash-free. */
START_TEST(test_jwks_oom_no_corruption)
{
	const char *json = "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\","
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"},"
		"{\"kty\":\"oct\",\"alg\":\"HS384\","
		"\"k\":\"YWFhYWJiYmJjY2NjZGRkZGVlZWVmZmZmZ2dnZ2hoaGg\"}]}";
	long n;

	SET_OPS();

	for (n = 1; n <= 20; n++) {
		jwk_set_t *jwk_set;

		g_alloc_count = 0;
		g_alloc_fail_at = n;
		ck_assert_int_eq(jwt_set_alloc(failing_malloc, failing_free), 0);

		jwk_set = jwks_create(json);

		/* Restore the default allocator before any assertion can
		 * longjmp out, so a later test never runs with the failing one. */
		g_alloc_fail_at = -1;
		jwt_set_alloc(NULL, NULL);

		/* Either the set failed to allocate, or it parsed; in both
		 * cases item access and teardown must be safe (no UAF / double
		 * free of the parsed tree). */
		if (jwk_set != NULL) {
			(void)jwks_item_get(jwk_set, 0);
			(void)jwks_item_get(jwk_set, 1);
			jwks_free(jwk_set);
		}
	}

	/* A clean full load with the default allocator still works. */
	g_alloc_fail_at = -1;
	{
		jwk_set_auto_t *ok = jwks_create(json);
		ck_assert_ptr_nonnull(ok);
		ck_assert_int_eq(jwks_error_any(ok), 0);
		ck_assert_int_eq(jwks_item_count(ok), 2);
	}
}
END_TEST

/* An ES256 token whose signature is a valid ECDSA size for a *different*
 * algorithm (96 bytes, the ES384 size) but wrong for the bound ES256/P-256 key
 * must be rejected. The MbedTLS backend previously accepted any of the three
 * ECDSA sizes and split R||S accordingly before verifying; it now requires the
 * exact size for the bound alg, matching OpenSSL. Rejection holds on all
 * backends. */
START_TEST(test_es256_wrong_size_sig)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] =
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0."
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	read_json("ec_key_prime256v1_pub.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_ES256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);

	free_key();
}
END_TEST

/* @rfc{8725,2.4} Duplicate members in the token header or payload must be
 * rejected so a peer that picks a different occurrence cannot disagree with us
 * about a claim/header. The Jansson backend rejects duplicates; json-c cannot
 * (it keeps the last occurrence), a documented limitation, so there the token
 * parses. */
START_TEST(test_dup_members_rejected)
{
	jwt_checker_auto_t *checker = NULL;
	/* {"alg":"none","alg":"none"} . {"iss":"x"} . */
	const char dup_hdr[] =
		"eyJhbGciOiJub25lIiwiYWxnIjoibm9uZSJ9.eyJpc3MiOiJ4In0.";
	/* {"alg":"none"} . {"iss":"a","iss":"b"} . */
	const char dup_pay[] =
		"eyJhbGciOiJub25lIn0.eyJpc3MiOiJhIiwiaXNzIjoiYiJ9.";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_NONE, NULL), 0);

	ret = jwt_checker_verify(checker, dup_hdr);
#ifdef HAVE_JSON_C
	/* json-c keeps the last occurrence; the token still parses/verifies. */
	ck_assert_int_eq(ret, 0);
#else
	ck_assert_int_ne(ret, 0);
#endif
	jwt_checker_error_clear(checker);

	ret = jwt_checker_verify(checker, dup_pay);
#ifdef HAVE_JSON_C
	ck_assert_int_eq(ret, 0);
#else
	ck_assert_int_ne(ret, 0);
#endif
}
END_TEST

/* @rfc{7519,4.1.4} A token that omits "exp" passes a default checker even with
 * the EXP check enabled (validate-if-present). Pin this documented behavior so
 * it cannot change silently. */
START_TEST(test_missing_exp_passes)
{
	jwt_checker_auto_t *checker = NULL;
	/* {"alg":"none"} . {"iss":"x"} . — no exp/nbf at all. */
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0.";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_NONE, NULL), 0);

	/* The default checker enables EXP/NBF, but a token lacking them is
	 * accepted (absence is not a failure). */
	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

/* base64url carries no padding, so a literal '=' inside a token segment is
 * invalid. The decoder now rejects it outright rather than silently stopping
 * at it and decoding only the prefix. (Downstream JSON/signature validation
 * also rejects the resulting truncation, so this is a conformance guard that
 * the malformed segment never decodes, not a bypass reproducer.) */
START_TEST(test_embedded_pad_rejected)
{
	jwt_checker_auto_t *checker = NULL;
	/* {"alg":"none"} . <payload with an embedded '='> . */
	const char token[] = "eyJhbGciOiJub25lIn0.eyJp=c3MiOiJ4In0.";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_NONE, NULL), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

/*
 * === A verify callback cannot strip the checker's key (GHSA-mhc9-xvg5-qg29) ===
 *
 * jwt_checker_setkey(c, JWT_ALG_NONE, key) takes the algorithm from the key, so
 * config->alg is JWT_ALG_NONE when the callback runs. A callback that set
 * config->key to NULL (e.g. a "kid" lookup that found nothing) left a checker
 * with neither a key nor an alg, which accepts exactly the unsigned tokens: a
 * forged {"alg":"none"} token verified. The key may be replaced, not removed.
 */
struct key_swap {
	const jwk_item_t *key;	/* what the callback leaves in config->key	*/
	int clear_alg;		/* ...and whether it also sets alg to none	*/
};

static int key_swap_cb(jwt_t *jwt, jwt_config_t *config)
{
	const struct key_swap *ks = config->ctx;

	(void)jwt;
	config->key = ks->key;
	if (ks->clear_alg)
		config->alg = JWT_ALG_NONE;

	return 0;
}

START_TEST(test_callback_cannot_strip_key)
{
	/* {"alg":"none"} . {"sub":"admin"} . (empty signature) */
	const char forged[] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
	const char *nokey = "Callback left no verification key";
	const jwt_alg_t algs[] = { JWT_ALG_NONE, JWT_ALG_ES256 };
	jwt_builder_auto_t *builder = NULL;
	char_auto *signed_tok = NULL;
	struct key_swap ks;
	size_t a;
	int clear;

	SET_OPS();

	read_json("ec_key_prime256v1.json");	/* "alg":"ES256" */

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, g_item), 0);
	signed_tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(signed_tok);

	/* setkey() with the key's own alg or an explicit one; the callback
	 * removes the key, and with clear_alg also the alg. */
	for (a = 0; a < ARRAY_SIZE(algs); a++) {
		for (clear = 0; clear < 2; clear++) {
			jwt_checker_auto_t *c = jwt_checker_new();

			ck_assert_ptr_nonnull(c);
			ck_assert_int_eq(jwt_checker_setkey(c, algs[a],
							    g_item), 0);

			/* No callback: the forgery never verified. */
			ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
			ck_assert_int_eq(jwt_checker_verify(c, signed_tok), 0);

			ks.key = NULL;
			ks.clear_alg = clear;
			ck_assert_int_eq(jwt_checker_setcb(c, key_swap_cb,
							   &ks), 0);

			ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), nokey);
			ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
			ck_assert_int_ne(jwt_checker_verify(c, signed_tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), nokey);

			/* Replacing the key is still allowed. */
			ks.key = g_item;
			ks.clear_alg = 0;
			ck_assert_int_eq(jwt_checker_verify(c, signed_tok), 0);
			ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c),
					 "Expected a signature, but JWT has none");
		}
	}

	/* Unchanged: a checker given no key at all, whose callback finds none
	 * either, verifies only unsigned tokens (see jwt_checker_setcb()). */
	{
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ks.key = NULL;
		ks.clear_alg = 0;
		ck_assert_int_eq(jwt_checker_setcb(c, key_swap_cb, &ks), 0);
		ck_assert_int_eq(jwt_checker_verify(c, forged), 0);
		ck_assert_int_ne(jwt_checker_verify(c, signed_tok), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "JWT has signature, but no key was given");
	}

	free_key();
}
END_TEST

/* ...nor by reconfiguring its own checker, which its ctx may well point to:
 * e.g. remembering a lookup with jwt_checker_setkey(ctx, JWT_ALG_NONE, found),
 * refreshing a keyring with jwt_checker_setkeyring(), or turning on
 * embedded-JWK verification. A key the checker held before the callback, or
 * was given since, means this token needs one, and so does the next. */
struct reconf {
	jwt_checker_t *checker;
	int how;
};

static int reconf_cb(jwt_t *jwt, jwt_config_t *config)
{
	const struct reconf *r = config->ctx;

	(void)jwt;
	switch (r->how) {
	case 0:	/* keyed: the lookup "remembered" its miss */
		ck_assert_int_eq(jwt_checker_setkey(r->checker, JWT_ALG_NONE,
						    NULL), 0);
		break;
	case 1:	/* keyed, then swapped to a keyring */
	case 3:	/* unkeyed, then given a keyring */
		ck_assert_int_eq(jwt_checker_setkeyring(r->checker, g_jwk_set,
					JWT_VERIFY_POLICY_ANY), 0);
		break;
	case 2:	/* unkeyed, then given a key */
		ck_assert_int_eq(jwt_checker_setkey(r->checker, JWT_ALG_NONE,
						    g_item), 0);
		break;
	case 4:	/* unkeyed, given a keyring and then no key again */
		ck_assert_int_eq(jwt_checker_setkeyring(r->checker, g_jwk_set,
					JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_eq(jwt_checker_setkey(r->checker, JWT_ALG_NONE,
						    NULL), 0);
		break;
	default: /* unkeyed, then given embedded-JWK verification */
		ck_assert_int_eq(jwt_checker_enable_embedded_jwk_keyring(
				r->checker, JWK_THUMBPRINT_SHA256, g_jwk_set), 0);
		break;
	}
	config->key = NULL;

	return 0;
}

START_TEST(test_callback_cannot_unkey_checker)
{
	/* {"alg":"none"} . {"sub":"admin"} . (empty signature) */
	const char forged[] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
	struct reconf r;

	SET_OPS();

	read_json("ec_key_prime256v1.json");	/* "alg":"ES256" */

	for (r.how = 0; r.how < 6; r.how++) {
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		if (r.how < 2)
			ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_NONE,
							    g_item), 0);
		r.checker = c;
		ck_assert_int_eq(jwt_checker_setcb(c, reconf_cb, &r), 0);

		ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 "Callback left no verification key");
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);

		/* Nor does the reconfiguration unkey the next token. */
		ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);
	}

	free_key();
}
END_TEST

/* A server reuses its checker. A callback that "remembers" its "kid" lookup
 * on it with jwt_checker_setkey(ctx, JWT_ALG_NONE, found) removes the key on a
 * miss, but the checker still requires one: the next forged token must not
 * meet an unkeyed checker. Likewise for a jti callback that does so. Only the
 * application, outside a verify, can make the checker unkeyed again. */
struct remember {
	jwt_checker_t *checker;
	const jwk_item_t *found;	/* the lookup's result */
};

static int remember_cb(jwt_t *jwt, jwt_config_t *config)
{
	const struct remember *r = config->ctx;

	(void)jwt;
	ck_assert_int_eq(jwt_checker_setkey(r->checker, JWT_ALG_NONE,
					    r->found), 0);
	config->key = r->found;

	return 0;
}

static int remember_jti_cb(const jwt_t *jwt, jwt_config_t *config,
			   const char *jti)
{
	const struct remember *r = config->ctx;

	(void)jwt;
	(void)jti;
	ck_assert_int_eq(jwt_checker_setkey(r->checker, JWT_ALG_NONE, NULL), 0);

	return 0;
}

START_TEST(test_callback_unkey_does_not_last)
{
	/* {"alg":"none"} . {"sub":"admin","jti":"1"} . (empty signature) */
	const char forged[] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImp0aSI6IjEifQ.";
	const char *nokey = "Callback left no verification key";
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *signed_tok = NULL;
	jwt_value_t jval;
	struct remember r;

	SET_OPS();

	read_json("ec_key_prime256v1.json");	/* "alg":"ES256" */

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, g_item), 0);
	jwt_set_SET_STR(&jval, "jti", "1");
	ck_assert_int_eq(jwt_builder_claim_set(builder, &jval),
			 JWT_VALUE_ERR_NONE);
	signed_tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(signed_tok);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_NONE, g_item), 0);
	r.checker = c;
	r.found = NULL;
	ck_assert_int_eq(jwt_checker_setcb(c, remember_cb, &r), 0);

	/* A miss: this token and every later one still need a key. */
	ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), nokey);
	ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), nokey);
	ck_assert_int_ne(jwt_checker_verify(c, signed_tok), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), nokey);

	/* A hit verifies; a miss after it still fails. */
	r.found = g_item;
	ck_assert_int_eq(jwt_checker_verify(c, signed_tok), 0);
	ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
	r.found = NULL;
	ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c), nokey);

	/* A jti callback that un-keys the checker after a verified token. */
	ck_assert_int_eq(jwt_checker_setcb(c, NULL, NULL), 0);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_NONE, g_item), 0);
	ck_assert_int_eq(jwt_checker_setjti(c, remember_jti_cb, &r), 0);
	ck_assert_int_eq(jwt_checker_verify(c, signed_tok), 0);
	ck_assert_int_ne(jwt_checker_verify(c, forged), 0);
	ck_assert_str_eq(jwt_checker_error_msg(c),
			 "A callback removed the checker's key");

	/* The application itself can still make the checker unkeyed. */
	ck_assert_int_eq(jwt_checker_setjti(c, NULL, NULL), 0);
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_NONE, NULL), 0);
	ck_assert_int_eq(jwt_checker_verify(c, forged), 0);
	ck_assert_int_ne(jwt_checker_verify(c, signed_tok), 0);

	free_key();
}
END_TEST

/* A callback cannot verify with its own checker (that freed the signature
 * list and embedded key the outer verify was using): the nested call fails. */
static int reenter_rc;
static char reenter_msg[256];

static int reenter_cb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_checker_t *c = config->ctx;

	(void)jwt;
	reenter_rc = jwt_checker_verify(c, "eyJhbGciOiJub25lIn0.e30.");
	snprintf(reenter_msg, sizeof(reenter_msg), "%s",
		 jwt_checker_error_msg(c));
	jwt_checker_error_clear(c);

	return 0;
}

START_TEST(test_callback_cannot_reenter)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;

	SET_OPS();

	read_json("ec_key_prime256v1.json");

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, g_item), 0);
	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkeyring(c, g_jwk_set,
				JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_setcb(c, reenter_cb, c), 0);

	reenter_rc = 0;
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	ck_assert_int_ne(reenter_rc, 0);
	ck_assert_str_eq(reenter_msg, "Checker is already verifying a token");
	ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);

	free_key();
}
END_TEST

/* Likewise jwt_checker_verify_detached(), which must fail before it touches
 * the checker: the outer verify keeps its signature count and results. */
static int reenter_detached_cb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_checker_t *c = config->ctx;

	(void)jwt;
	reenter_rc = jwt_checker_verify_detached(c, "eyJhbGciOiJub25lIn0..",
						 (const unsigned char *)"{}",
						 2);
	snprintf(reenter_msg, sizeof(reenter_msg), "%s",
		 jwt_checker_error_msg(c));
	jwt_checker_error_clear(c);

	return 0;
}

START_TEST(test_callback_cannot_reenter_detached)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;

	SET_OPS();

	read_json("ec_key_prime256v1.json");

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, g_item), 0);
	tok = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_ptr_nonnull(c);
	ck_assert_int_eq(jwt_checker_setkeyring(c, g_jwk_set,
				JWT_VERIFY_POLICY_ANY), 0);
	ck_assert_int_eq(jwt_checker_setcb(c, reenter_detached_cb, c), 0);

	reenter_rc = 0;
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	ck_assert_int_ne(reenter_rc, 0);
	ck_assert_str_eq(reenter_msg, "Checker is already verifying a token");
	ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
	ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
	ck_assert_ptr_nonnull(jwt_checker_sig_key(c, 0));

	free_key();
}
END_TEST

/*
 * === JSON backend parity ===
 *
 * The json-c backend must accept and reject what the Jansson one does. json-c
 * stores a JSON null as a NULL pointer, which reads as a missing value, and
 * decodes "\u0000" into strings that libjwt then reads as C strings.
 */

/* A JWKS that is just the JSON null. Jansson hands it to the JWK parser,
 * which finds no "kty" in it. json-c has no object for a null, so the parse
 * fails, and that failure needs an error message like any other (it used to
 * leave the message uninitialized). */
START_TEST(test_jwks_top_level_null)
{
	jwk_set_auto_t *jwk_set = NULL;

	SET_OPS();

	jwk_set = jwks_create("null\n");
	ck_assert_ptr_nonnull(jwk_set);
#ifdef HAVE_JSON_C
	ck_assert_int_ne(jwks_error(jwk_set), 0);
	ck_assert_str_eq(jwks_error_msg(jwk_set),
			 "<buffer>: JSON null is not supported");
#else
	ck_assert_int_eq(jwks_error(jwk_set), 0);
	ck_assert_int_eq(jwks_error_any(jwk_set), 1);
#endif
}
END_TEST

/* The oct_key_256.json key, with a "kid". */
static const char oct_k1[] = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\","
	"\"alg\":\"HS256\","
	"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}]}";

/* Copy @tok with @ins added to the end of its "@member" string value. */
static char *add_to_member(const char *tok, const char *member,
			   const char *ins)
{
	char key[32], *out;
	const char *p, *q;
	size_t n;

	snprintf(key, sizeof(key), "\"%s\":\"", member);
	p = strstr(tok, key);
	ck_assert_ptr_nonnull(p);
	q = strchr(p + strlen(key), '"');
	ck_assert_ptr_nonnull(q);

	n = (size_t)(q - tok);
	out = malloc(strlen(tok) + strlen(ins) + 1);
	ck_assert_ptr_nonnull(out);
	memcpy(out, tok, n);
	strcpy(out + n, ins);
	strcat(out, q);

	return out;
}

/* "\u0000" in a token is refused, as Jansson refuses it. json-c decoded it and
 * libjwt read the string, or object key, only up to the NUL, so the rest of
 * it was never checked. */
START_TEST(test_json_nul_in_token)
{
	/* {"alg":"HS256","kid":"k1\u0000junk"} . {"sub":"x"} . <HS256, k1> */
	const char kid_nul[] =
		"eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxXHUwMDAwanVuayJ9"
		".eyJzdWIiOiJ4In0"
		".8MzlsCu49jA_Z9sYEsQrW9OxaQ9rKSj9KaTS7fcuozo";
	/* {"alg":"HS256","kid":"k1"} . {"sub":"x"} . <HS256, k1> */
	const char kid_ok[] =
		"eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0"
		".eyJzdWIiOiJ4In0"
		"._jMbhBP7jZR_aqUP8yxL3FpgdHwn94YnEvz8WWzD3iE";
	/* "aud" as pinned, then with a NUL in its value, or in its key. */
	const char * const claims[] = {
		"{\"aud\":\"api\"}",
		"{\"aud\":\"api\\u0000.attacker.example\"}",
		"{\"aud\\u0000x\":\"api\"}",
	};
	const char * const members[] = { "payload", "protected", "signature" };
	jwk_set_auto_t *ring = NULL;
	size_t i, m;
	int b64, ret;

	SET_OPS();

	read_json("oct_key_256.json");

	/* A "kid" does not select the key named by its prefix. */
	ring = jwks_create(oct_k1);
	ck_assert_ptr_nonnull(ring);
	ck_assert_int_eq(jwks_error_any(ring), 0);
	{
		jwt_checker_auto_t *c = jwt_checker_new();

		ck_assert_ptr_nonnull(c);
		ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
					JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_eq(jwt_checker_verify(c, kid_ok), 0);
		ck_assert_int_ne(jwt_checker_verify(c, kid_nul), 0);
	}

	/* A claim is not compared by its prefix (a signed raw payload). The
	 * first entry is the control. */
	for (i = 0; i < ARRAY_SIZE(claims); i++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_nonnull(c);
		ret = jwt_builder_setkey(b, JWT_ALG_HS256, g_item);
		ck_assert_int_eq(ret, 0);
		ret = jwt_builder_setpayload(b,
				(const unsigned char *)claims[i],
				strlen(claims[i]));
		ck_assert_int_eq(ret, 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ret = jwt_checker_setkey(c, JWT_ALG_HS256, g_item);
		ck_assert_int_eq(ret, 0);
		ret = jwt_checker_claim_set(c, JWT_CLAIM_AUD, "api");
		ck_assert_int_eq(ret, 0);

		ret = jwt_checker_verify(c, tok);
		if (i == 0)
			ck_assert_int_eq(ret, 0);
		else
			ck_assert_int_ne(ret, 0);
	}

	/* No member of a JWS JSON token, base64url or unencoded, is checked
	 * only up to a NUL. */
	for (b64 = 1; b64 >= 0; b64--) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_ptr_nonnull(b);
		ck_assert_ptr_nonnull(c);
		ret = jwt_builder_setkey(b, JWT_ALG_HS256, g_item);
		ck_assert_int_eq(ret, 0);
		ret = jwt_builder_set_format(b, JWT_FORMAT_JSON_FLAT);
		ck_assert_int_eq(ret, 0);
		if (!b64) {
			ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
			ret = jwt_builder_setpayload(b,
					(const unsigned char *)"$.02", 4);
			ck_assert_int_eq(ret, 0);
		}
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ret = jwt_checker_setkey(c, JWT_ALG_HS256, g_item);
		ck_assert_int_eq(ret, 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

		for (m = 0; m < ARRAY_SIZE(members); m++) {
			char_auto *bad = add_to_member(tok, members[m],
						       "\\u0000;unsigned");

			ck_assert_int_ne(jwt_checker_verify(c, bad), 0);
		}
	}

	free_key();
}
END_TEST

/* Likewise in a JWK or JWKS, from a string, a FILE * or a file. */
START_TEST(test_json_nul_in_jwks)
{
	const char value[] = "{\"kty\":\"oct\",\"kid\":\"a\\u0000b\","
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}";
	const char key[] = "{\"kty\\u0000x\":\"oct\","
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}";
	char path[] = "/tmp/libjwt_nul_XXXXXX";
	jwk_set_t *set;
	FILE *fp;
	int fd;

	SET_OPS();

	set = jwks_create(value);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_ptr_nonnull(strstr(jwks_error_msg(set),
				     "\\u0000 is not allowed"));
	jwks_free(set);

	set = jwks_create(key);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	jwks_free(set);

	fd = mkstemp(path);
	ck_assert_int_ge(fd, 0);
	fp = fdopen(fd, "w+");
	ck_assert_ptr_nonnull(fp);
	ck_assert_int_ge(fputs(value, fp), 0);
	ck_assert_int_eq(fflush(fp), 0);
	rewind(fp);

	set = jwks_create_fromfp(fp);
	fclose(fp);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_ptr_nonnull(strstr(jwks_error_msg(set),
				     "\\u0000 is not allowed"));
	jwks_free(set);

	set = jwks_create_fromfile(path);
	unlink(path);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_ptr_nonnull(strstr(jwks_error_msg(set),
				     "\\u0000 is not allowed"));
	jwks_free(set);

	/* A file that cannot be opened is named in the error. */
	set = jwks_create_fromfile(path);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_ptr_nonnull(strstr(jwks_error_msg(set), path));
	jwks_free(set);
}
END_TEST

/* A JWKS file is one JSON value, as a string or a FILE * is: a second one
 * after it is refused, as with Jansson (json-c used to load the first and
 * ignore the rest), while trailing whitespace is fine. */
START_TEST(test_jwks_file_trailing_data)
{
#define OCT_K1	"{\"kty\":\"oct\",\"kid\":\"k1\"," \
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}"
	static const struct {
		const char *doc;
		int ok;
	} files[] = {
		{ OCT_K1 "\r\n \t\n", 1 },
		{ OCT_K1 "\n" OCT_K1 "\n", 0 },
		{ OCT_K1 "]", 0 },
	};
#undef OCT_K1
	size_t f;

	SET_OPS();

	for (f = 0; f < ARRAY_SIZE(files); f++) {
		char path[] = "/tmp/libjwt_trail_XXXXXX";
		jwk_set_auto_t *set = NULL;
		FILE *fp;
		int fd;

		fd = mkstemp(path);
		ck_assert_int_ge(fd, 0);
		fp = fdopen(fd, "w");
		ck_assert_ptr_nonnull(fp);
		ck_assert_int_ge(fputs(files[f].doc, fp), 0);
		ck_assert_int_eq(fclose(fp), 0);

		set = jwks_create_fromfile(path);
		unlink(path);
		ck_assert_ptr_nonnull(set);

		if (files[f].ok) {
			ck_assert_int_eq(jwks_error_any(set), 0);
			ck_assert_ptr_nonnull(jwks_find_bykid(set, "k1"));
		} else {
			ck_assert_int_ne(jwks_error(set), 0);
			ck_assert_ptr_null(jwks_item_get(set, 0));
		}
	}
}
END_TEST

/* A protected header the builder will not produce, and its HS256 signature
 * (oct_key_256.json) over it and the payload {"sub":"x"}. */
struct signed_hdr {
	const char *prot;
	const char *sig;
};

#define SUB_X	"eyJzdWIiOiJ4In0"

static char *hdr_compact(const struct signed_hdr *h)
{
	char *tok = NULL;

	ck_assert_int_gt(asprintf(&tok, "%s." SUB_X ".%s", h->prot, h->sig), 0);

	return tok;
}

/* Flattened JWS JSON, with @extra (",\"member\":...") added. */
static char *hdr_flat(const struct signed_hdr *h, const char *extra)
{
	char *tok = NULL;

	ck_assert_int_gt(asprintf(&tok, "{\"payload\":\"" SUB_X "\","
				  "\"protected\":\"%s\","
				  "\"signature\":\"%s\"%s}",
				  h->prot, h->sig, extra), 0);

	return tok;
}

/* General JWS JSON, with @entry_extra added to the signature and @extra to
 * the top level. */
static char *hdr_general(const struct signed_hdr *h, const char *entry_extra,
			 const char *extra)
{
	char *tok = NULL;

	ck_assert_int_gt(asprintf(&tok, "{\"payload\":\"" SUB_X "\","
				  "\"signatures\":[{\"protected\":\"%s\","
				  "\"signature\":\"%s\"%s}]%s}",
				  h->prot, h->sig, entry_extra, extra), 0);

	return tok;
}

/* Verify @tok with oct_key_256.json (g_item) as the key, or in a keyring.
 * Returns the checker's error message, or NULL if the token verified. */
static char verify_msg[256];

static const char *hdr_verify(const char *tok, int keyring,
			      const char *understood)
{
	/* Declared first, so freed after the checker that borrows it. */
	jwk_set_auto_t *ring = NULL;
	jwt_checker_auto_t *c = jwt_checker_new();
	int ret;

	ck_assert_ptr_nonnull(c);
	if (keyring) {
		ring = jwks_create(oct_k1);
		ck_assert_ptr_nonnull(ring);
		ret = jwt_checker_setkeyring(c, ring, JWT_VERIFY_POLICY_ANY);
	} else {
		ret = jwt_checker_setkey(c, JWT_ALG_HS256, g_item);
	}
	ck_assert_int_eq(ret, 0);
	if (understood)
		ck_assert_int_eq(jwt_checker_understands(c, understood), 0);

	if (!jwt_checker_verify(c, tok))
		return NULL;

	snprintf(verify_msg, sizeof(verify_msg), "%s",
		 jwt_checker_error_msg(c));

	return verify_msg;
}

/* {"alg":"HS256"}, a control */
static const struct signed_hdr hdr_plain = {
	"eyJhbGciOiJIUzI1NiJ9",
	"oCDDLEY9LLM6yy33vqb9kIlJU2zwtY6uiPeA70BVO0o",
};

/* {"alg":"HS256","crit":[null,"zzz"],"zzz":1} */
static const struct signed_hdr hdr_crit_null_entry = {
	"eyJhbGciOiJIUzI1NiIsImNyaXQiOltudWxsLCJ6enoiXSwienp6IjoxfQ",
	"1zMxEaDZGbbCreycvd0FtTsLKqB1HRbsMwXqBqoDJ5c",
};

/* A JSON null in an array is an element like any other. json-c returns NULL
 * for it, which used to end jwt_json_arr_foreach() there, so later elements
 * were skipped: here the unknown critical "zzz", and in a JWK the "x5c" and
 * "key_ops" entries. */
START_TEST(test_json_null_array_element)
{
	const char *entries = "\"crit\" header entries must be strings";
	char_auto *compact = NULL, *flat = NULL;
	jwk_set_auto_t *ops = NULL, *x5c = NULL;
	const jwk_item_t *item;
	int keyring;

	SET_OPS();

	read_json("oct_key_256.json");

	compact = hdr_compact(&hdr_crit_null_entry);
	flat = hdr_flat(&hdr_crit_null_entry, "");

	for (keyring = 0; keyring < 2; keyring++) {
		char_auto *plain = hdr_compact(&hdr_plain);

		ck_assert_ptr_null(hdr_verify(plain, keyring, NULL));
		ck_assert_str_eq(hdr_verify(compact, keyring, NULL), entries);
		ck_assert_str_eq(hdr_verify(flat, keyring, NULL), entries);
	}

	ops = jwks_create("{\"kty\":\"oct\",\"key_ops\":[null,\"verify\"],"
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}");
	ck_assert_ptr_nonnull(ops);
	item = jwks_item_get(ops, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);
	ck_assert_int_eq(jwks_item_key_ops(item), JWK_KEY_OP_VERIFY);

	x5c = jwks_create("{\"kty\":\"oct\",\"x5c\":[null],"
		"\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}");
	ck_assert_ptr_nonnull(x5c);
	item = jwks_item_get(x5c, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);
	ck_assert_str_eq(jwks_item_error_msg(item),
			 "Invalid JWK: \"x5c\" entry is not a string");

	/* A null "keys" entry is an item with an error, and the keys around
	 * it still load; the set itself has no error. */
	{
		jwk_set_auto_t *keys = jwks_create("{\"keys\":[null,"
			"{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":"
			"\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\"}]}");

		ck_assert_ptr_nonnull(keys);
		ck_assert_int_eq(jwks_error(keys), 0);
		ck_assert_int_eq(jwks_item_count(keys), 2);
		item = jwks_item_get(keys, 0);
		ck_assert_int_ne(jwks_item_error(item), 0);
		ck_assert_str_eq(jwks_item_error_msg(item),
				 "Invalid JWK: missing kty value");
		item = jwks_item_get(keys, 1);
		ck_assert_int_eq(jwks_item_error(item), 0);
		ck_assert_ptr_eq(jwks_find_bykid(keys, "k1"), item);
	}

	free_key();
}
END_TEST

/* {"alg":"HS256","b64":null} */
static const struct signed_hdr hdr_b64_null = {
	"eyJhbGciOiJIUzI1NiIsImI2NCI6bnVsbH0",
	"m3RTDYq5KVSlqxmxvwC2vnk8E_gFJrb-X7lijcyRNqU",
};

/* {"alg":"HS256","crit":null} */
static const struct signed_hdr hdr_crit_null = {
	"eyJhbGciOiJIUzI1NiIsImNyaXQiOm51bGx9",
	"98XF7LFGKGiO9lSX8b9QCNLMY4jUv6NK3SYFpwnmSFA",
};

/* {"alg":"HS256","crit":["x"],"x":null} */
static const struct signed_hdr hdr_crit_x_null = {
	"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieCJdLCJ4IjpudWxsfQ",
	"Y-u1MP_xvDl-R_E5AXYrb2MSAv18AkCnPrJtBg-dORE",
};

/* A member that is JSON null is present, with a value of the wrong type.
 * json-c's jwt_json_obj_get() gives NULL for it, as for a missing member, so
 * these were taken as absent there. */
START_TEST(test_json_null_member)
{
	const char *b64 = "\"b64\" header must be a boolean";
	const char *crit = "\"crit\" header must be an array";
	const char *unprot =
		"JWS \"crit\"/\"b64\" must be in the protected header";
	const char *header = "JWS unprotected header is invalid or overlaps";
	const char *mixed = "JWS JSON mixes General and Flattened members";
	int keyring;

	SET_OPS();

	read_json("oct_key_256.json");

	/* In the protected header, Compact or JSON, key or keyring. A null
	 * parameter listed in "crit" is in the header. */
	for (keyring = 0; keyring < 2; keyring++) {
		char_auto *b64_c = hdr_compact(&hdr_b64_null);
		char_auto *b64_f = hdr_flat(&hdr_b64_null, "");
		char_auto *crit_c = hdr_compact(&hdr_crit_null);
		char_auto *crit_f = hdr_flat(&hdr_crit_null, "");
		char_auto *x_c = hdr_compact(&hdr_crit_x_null);

		ck_assert_str_eq(hdr_verify(b64_c, keyring, NULL), b64);
		ck_assert_str_eq(hdr_verify(b64_f, keyring, NULL), b64);
		ck_assert_str_eq(hdr_verify(crit_c, keyring, NULL), crit);
		ck_assert_str_eq(hdr_verify(crit_f, keyring, NULL), crit);
		ck_assert_ptr_null(hdr_verify(x_c, keyring, "x"));
	}

	/* In an unprotected header, or as the unprotected header. */
	{
		char_auto *crit_f = hdr_flat(&hdr_plain,
					     ",\"header\":{\"crit\":null}");
		char_auto *b64_g = hdr_general(&hdr_plain,
				",\"header\":{\"b64\":null}", "");
		char_auto *hdr_f = hdr_flat(&hdr_plain, ",\"header\":null");
		char_auto *hdr_g = hdr_general(&hdr_plain, ",\"header\":null",
					       "");

		ck_assert_str_eq(hdr_verify(crit_f, 0, NULL), unprot);
		ck_assert_str_eq(hdr_verify(b64_g, 0, NULL), unprot);
		ck_assert_str_eq(hdr_verify(hdr_f, 0, NULL), header);
		ck_assert_str_eq(hdr_verify(hdr_g, 0, NULL), header);
	}

	/* General and Flattened members do not mix. */
	{
		char_auto *flat = hdr_flat(&hdr_plain, "");
		char_auto *general = hdr_general(&hdr_plain, "", "");
		char_auto *sigs = hdr_flat(&hdr_plain, ",\"signatures\":null");
		char_auto *prot = hdr_general(&hdr_plain, "",
					      ",\"protected\":null");
		char_auto *sig = hdr_general(&hdr_plain, "",
					     ",\"signature\":null");
		char_auto *hdr = hdr_general(&hdr_plain, "",
					     ",\"header\":null");

		ck_assert_ptr_null(hdr_verify(flat, 0, NULL));
		ck_assert_ptr_null(hdr_verify(general, 0, NULL));
		ck_assert_str_eq(hdr_verify(sigs, 0, NULL), mixed);
		ck_assert_str_eq(hdr_verify(prot, 0, NULL), mixed);
		ck_assert_str_eq(hdr_verify(sig, 0, NULL), mixed);
		ck_assert_str_eq(hdr_verify(hdr, 0, NULL), mixed);
		ck_assert_str_eq(hdr_verify("{\"payload\":\"" SUB_X "\","
					    "\"signatures\":null}", 0, NULL),
				 "\"signatures\" must be an array");
	}

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
	TCase *tc_json_parity;
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
	tcase_add_loop_test(tc_jwks_json, test_jwks_okp_x25519_bad_x_len, 0, i);
	tcase_add_loop_test(tc_jwks_json, test_jwks_okp_x25519_bad_d_len, 0, i);
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
	tcase_add_loop_test(tc_alg_confusion,
			    test_rsa_short_signature_oob, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_exp_out_of_range_int, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_jwks_oom_no_corruption, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_es256_wrong_size_sig, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_dup_members_rejected, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_missing_exp_passes, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_embedded_pad_rejected, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_callback_cannot_strip_key, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_callback_cannot_unkey_checker, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_callback_unkey_does_not_last, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_callback_cannot_reenter, 0, i);
	tcase_add_loop_test(tc_alg_confusion,
			    test_callback_cannot_reenter_detached, 0, i);

	tcase_set_timeout(tc_alg_confusion, 30);
	suite_add_tcase(s, tc_alg_confusion);

	/* json-c behaves as Jansson does */
	tc_json_parity = tcase_create("json_parity");

	tcase_add_loop_test(tc_json_parity, test_jwks_top_level_null, 0, i);
	tcase_add_loop_test(tc_json_parity, test_json_nul_in_token, 0, i);
	tcase_add_loop_test(tc_json_parity, test_json_nul_in_jwks, 0, i);
	tcase_add_loop_test(tc_json_parity, test_jwks_file_trailing_data, 0, i);
	tcase_add_loop_test(tc_json_parity, test_json_null_array_element, 0, i);
	tcase_add_loop_test(tc_json_parity, test_json_null_member, 0, i);

	tcase_set_timeout(tc_json_parity, 30);
	suite_add_tcase(s, tc_json_parity);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Security Regression Tests");
}
