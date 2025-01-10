/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

#ifdef JWT_CONSTRUCTOR
START_TEST(test_jwt_crypto_ops)
{
	const char *msg = getenv("JWT_CRYPTO");

	ck_assert_str_eq(msg, "openssl");
}
END_TEST
#endif

/* The simplest of tests */
START_TEST(test_jwt_new)
{
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	EMPTY_JWT(jwt);
}
END_TEST

START_TEST(test_jwt_dup)
{
	jwt_auto_t *jwt = NULL, *new = NULL;
	jwt_value_t jval;
	int ret = 0;
	const char *val = NULL;
	time_t now;
	long valint;

	SET_OPS();

	new = jwt_dup(NULL);
	ck_assert_ptr_null(new);

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", "test");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert_ptr_nonnull(new);

	jwt_set_GET_STR(&jval, "iss");
	ret = jwt_grant_get(new, &jval);
	val = jval.str_val;
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, "test");

	ck_assert_int_eq(jwt_get_alg(new), JWT_ALG_NONE);

	now = time(NULL);
	jwt_set_ADD_INT(&jval, "iat", (long)now);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "iat");
	ret = jwt_grant_get(jwt, &jval);
	valint = jval.int_val;
	ck_assert(((long)now) == valint);
}
END_TEST

START_TEST(test_jwt_dup_signed)
{
	jwt_test_auto_t *jwt = NULL;
	jwt_auto_t *new = NULL;
	jwt_value_t jval;
	int ret = 0;
	const char *val = NULL;

	SET_OPS();

	CREATE_JWT(jwt, "oct_key_256.json", JWT_ALG_HS256);

	jwt_set_ADD_STR(&jval, "iss", "test");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert_ptr_nonnull(new);

	jwt_set_GET_STR(&jval, "iss");
	ret = jwt_grant_get(new, &jval);
	val = jval.str_val;
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, "test");

	ck_assert_int_eq(jwt_get_alg(new), JWT_ALG_HS256);
}
END_TEST

START_TEST(test_jwt_verify)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJmaWxlcy5jeXBo"
			     "cmUuY29tIiwic3ViIjoidXNlcjAifQ.";
	jwt_alg_t alg;
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	alg = jwt_get_alg(jwt);
	ck_assert_int_eq(alg, JWT_ALG_NONE);
}
END_TEST

static int test_jwt_verify_alg_none_cb(const jwt_t *jwt, jwt_config_t *config)
{
	jwt_alg_t alg = jwt_get_alg(jwt);
	jwt_alg_t *test = config->ctx;

	ck_assert_ptr_nonnull(test);
	ck_assert_ptr_null(config->jw_key);

	/* Passed to us. */
	ck_assert_int_eq(*test, JWT_ALG_HS256);

	*test = JWT_ALG_NONE;

	return (alg == JWT_ALG_NONE) ? 0 : -1;
}

START_TEST(test_jwt_verify_wcb_alg_none)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJmaWxlcy5jeXBo"
			     "cmUuY29tIiwic3ViIjoidXNlcjAifQ.";
	JWT_CONFIG_DECLARE(config);
	jwt_alg_t alg = JWT_ALG_HS256;
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	config.ctx = &alg;

	jwt = jwt_verify_wcb(token, &config, test_jwt_verify_alg_none_cb);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	ck_assert_int_eq(alg, JWT_ALG_NONE);

	alg = jwt_get_alg(jwt);
	ck_assert_int_eq(alg, JWT_ALG_NONE);
}

START_TEST(test_jwt_verify_invalid_final_dot)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

START_TEST(test_jwt_verify_invalid_alg)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIQUhBSCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

/* { "typ": "JWT", "alg": "none" } . . */
START_TEST(test_jwt_verify_dot_dot)
{
	JWT_CONFIG_DECLARE(config);
	char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..";
	jwt_auto_t *jwt = NULL;
	int ret;

	SET_OPS();

	/* Two dots */
	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);

	/* One dot */
	ret = strlen(token);
	token[ret - 1] = '\0';

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);

	/* No dot */
	ret = strlen(token);
	token[ret - 1] = '\0';

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}

/* { "typ": "JWT", "alg": "none" } . {} . */
START_TEST(test_jwt_verify_empty_body)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.e30.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
        ck_assert_int_eq(jwt_error(jwt), 0);
}

/* { "typ": "JWT", "alg": "HS256" } . { "test": 1 } . */
START_TEST(test_jwt_verify_nokey_alg_hs256)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJBTEwiLCJhbGciOiJOT05FIn0.eyJ0ZXN0IjoxfQ.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
        ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

/* { "typ": "ALL", "alg": "none" } . { "test": 1 } */
START_TEST(test_jwt_verify_ignore_typ)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJBTEwiLCJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
        ck_assert_int_eq(jwt_error(jwt), 0);
}
END_TEST

START_TEST(test_jwt_verify_invalid_head)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "yJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

START_TEST(test_jwt_verify_alg_none_with_key)
{
	const char token[] = "eyJhbGciOiJub25lIn0."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_256.json");
	ck_assert_ptr_nonnull(g_item);
	config.jw_key = g_item;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);

	free_key();
}
END_TEST

START_TEST(test_jwt_verify_invalid_body)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

START_TEST(test_jwt_verify_hs256)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQi"
		"OjE3MzYxMTM5OTIsInN1YiI6InVzZXIwIn0.74dWICs1ezbHNBrPSmop3o"
		"zc4GQ8YdZISXCxZX8LAjk";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_256.json");
	config.jw_key = g_item;
	config.alg = JWT_ALG_HS256;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	free_key();
}
END_TEST

/* Fron issue #201. Adding tests for alg checks. */
/* { "typ": "JWT", "alg": "HS256" } . { ... } . sig */
START_TEST(test_jwt_verify_hs256_no_key_alg)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
			     "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
			     "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

START_TEST(test_jwt_verify_hs256_issue_1)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi"
		"OiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE"
		"5hbWUiOiJ3b3JsZCIsInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3Ro"
		"ZXIiXSwiaXNzIjoiaXNzdWVyIiwicGVyc29uSWQiOiI3NWJiM2NjNy1iOT"
		"MzLTQ0ZjAtOTNjNi0xNDdiMDgyZmFkYjUiLCJleHAiOjE5MDg4MzUyMDAs"
		"ImlhdCI6MTQ4ODgxOTYwMCwidXNlcm5hbWUiOiJoZWxsby53b3JsZCJ9.t"
		"JoAl_pvq95hK7GKqsp5TU462pLTbmSYZc1fAHzcqWM";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_256_issue1.json");

	config.jw_key = g_item;
	config.alg = JWT_ALG_HS256;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	free_key();
}
END_TEST

START_TEST(test_jwt_verify_hs256_issue_2)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQi"
		"OjE3MzYxMTQyOTIsInN1YiI6InVzZXIwIn0.CjttUxGvPjKIh1Cz8RAOoB"
		"9i6xHKexJAsWzKwd6C7uM";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_256_issue2.json");
	config.jw_key = g_item;
	config.alg = JWT_ALG_HS256;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	free_key();
}
END_TEST

START_TEST(test_jwt_verify_hs384)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQi"
		"OjE3MzYxMTQxMTAsInN1YiI6InVzZXIwIn0.9bqi8aIAAS1L8uaOCFum-z"
		"oHC96tJOuDHW9GzE7uUQbXPyg6FmXQ9LS92D1aQi82";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_384.json");
	config.jw_key = g_item;
	config.alg = JWT_ALG_HS384;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	free_key();
}
END_TEST

START_TEST(test_jwt_verify_hs512)
{
	JWT_CONFIG_DECLARE(config);
        const char token[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQi"
		"OjE3MzYxMTQxNzAsInN1YiI6InVzZXIwIn0.WSD1YRRDD58uG-EeNGVhZt"
		"kDHgi_EVbJBHvCt72mE7oVFJ9qU8WCx5ACMbyIuWdgvOozTUVCSHL6RtDo"
		"JMq4JQ";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_512.json");
	config.jw_key = g_item;
	config.alg = JWT_ALG_HS512;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	free_key();
}
END_TEST

static int test_jwt_verify_wcb_hs512_kp(const jwt_t *jwt, jwt_config_t *config)
{
	if (jwt_get_alg(jwt) != JWT_ALG_HS512)
		return EINVAL;

	config->jw_key = g_item;

	return 0;
}

START_TEST(test_jwt_verify_wcb_hs512)
{
        const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3Mi"
			     "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
			     "Q.u-4XQB1xlYV8SgAnKBof8fOWOtfyNtc1ytTlc_vHo0U"
			     "lh5uGT238te6kSacnVzBbC6qwzVMT1806oa1Y8_8EOg";
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_512_wcb.json");

	config.alg = JWT_ALG_HS512;

	jwt = jwt_verify_wcb(token, &config, &test_jwt_verify_wcb_hs512_kp);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_eq(jwt_error(jwt), 0);

	ck_assert_ptr_eq(config.jw_key, g_item);

	free_key();
}
END_TEST

START_TEST(test_jwt_verify_wcb_invalid)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.xqea3OVgPEMxsCgyikr"
			     "R3gGv4H2yqMyXMm7xhOlQWpA-NpT6n2a1d7TD"
			     "GgU6LOe4";
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	config.alg = JWT_ALG_HS512;

	jwt = jwt_verify_wcb(token, &config, &test_jwt_verify_wcb_hs512_kp);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
	ck_assert_str_eq(jwt_error_msg(jwt), "User callback returned error");
}
END_TEST

START_TEST(test_jwt_verify_wcb_invalid_body)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	config.alg = JWT_ALG_HS512;

	jwt = jwt_verify_wcb(token, &config,
			     &test_jwt_verify_wcb_hs512_kp);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
	ck_assert_str_eq(jwt_error_msg(jwt), "Error parsing body");
}
END_TEST

START_TEST(test_jwt_verify_invalid_base64)
{
	JWT_CONFIG_DECLARE(config);
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
			     "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
			     "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBga";
	jwt_auto_t *jwt = NULL;

	SET_OPS();

	read_key("oct_key_256_invalid_base64.json");
	config.jw_key = g_item;
	config.alg = JWT_ALG_HS256;

	jwt = jwt_verify(token, &config);
	ck_assert_ptr_nonnull(jwt);
        ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_new");

#ifdef JWT_CONSTRUCTOR
	tcase_add_test(tc_core, test_jwt_crypto_ops);
#endif

	tcase_add_loop_test(tc_core, test_jwt_new, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dup, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dup_signed, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_wcb_alg_none, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_alg, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_ignore_typ, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_dot_dot, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_empty_body, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_nokey_alg_hs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_head, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_alg_none_with_key, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_body, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_wcb_invalid_body, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_final_dot, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_hs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_hs256_no_key_alg, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_hs384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_hs512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_wcb_hs512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_wcb_invalid, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_base64, 0, i);

	tcase_add_loop_test(tc_core, test_jwt_verify_hs256_issue_1, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_hs256_issue_2, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT New");
}
