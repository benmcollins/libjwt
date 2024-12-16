/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwt_encode_fp)
{
	FILE *out;
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	/* TODO Write to actual file and read back to validate output. */
#ifdef _WIN32
	out = fopen("nul", "w");
#else
	out = fopen("/dev/null", "w");
#endif
	ck_assert_ptr_ne(out, NULL);

	ret = jwt_encode_fp(jwt, out);
	ck_assert_int_eq(ret, 0);

	fclose(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_str)
{
	const char res[] = "eyJhbGciOiJub25lIn0.eyJpYXQiOjE0NzU5ODA1NDUsIml"
		"zcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6IlhYWFgtWVlZW"
		"S1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_alg_none)
{
	const char res[] = "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ3d3cucGx1Z2dlcnM"
		"ubmwiLCJleHAiOjE0Nzc1MTQ4MTIsInN1YiI6IlBsdWdnZXJzIFNvZnR3YXJlIn0.";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "aud", "www.pluggers.nl");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "exp", 1477514812);
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "Pluggers Software");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, NULL, 0);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs256)
{
	const char res[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.ezbB-vH0KoNU5aA6apcJ1JNorI2HnD8s0yp7zdXt42M";
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS256, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs384)
{
	const char res[] = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.jiOTkn_HXFz1eff2rx4bh2USfCVFh_YigoJP77Baf2d9wtQn6TBxqXmo"
		"kdQtTDQm";
	unsigned char key384[48] = "aaaabbbbccccddddeeeeffffgggghhhh"
				   "iiiijjjjkkkkllll";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS384, key384, sizeof(key384));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs512)
{
	const char res[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.OgEFcuV7zY3A-_3YgBzZqdMXW09CGDznMuqoHh5Ln2i18UJ3pf6WdMec"
		"zlBniP2LzuS_fWJRpHMOuofeMHgU3Q";
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_change_alg)
{
	const char res[] = "eyJhbGciOiJub25lIn0.eyJpYXQiOjE0NzU5ODA1NDUsIml"
		"zcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6IlhYWFgtWVlZW"
		"S1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.";
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, NULL, 0);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_invalid)
{
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, NULL, sizeof(key512));
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, 0);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, key512, sizeof(key512));
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, key512, 0);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, NULL, sizeof(key512));
	ck_assert_int_eq(ret, EINVAL);

	/* Set a value that will never happen. */
	ret = jwt_set_alg(jwt, 999, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_decode)
{
	const char *key = "somestring";
	jwt_t *mytoken, *ymtoken;
	char *encoded;
	int rc;

	SET_OPS();

	jwt_new(&mytoken);
	jwt_add_grant(mytoken, "sub", "user0");
	jwt_add_grant_int(mytoken, "iat", 1619130517);
	jwt_add_grant_int(mytoken, "exp", 1619216917);
	jwt_set_alg(mytoken, JWT_ALG_HS256, (unsigned char *)key, strlen(key));

	encoded = jwt_encode_str(mytoken);
	rc = jwt_decode(&ymtoken, encoded, (unsigned char *)key, strlen(key));
	ck_assert_int_eq(rc, 0);

	jwt_free(mytoken);
	jwt_free(ymtoken);
	free(encoded);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_encode");

	tcase_add_loop_test(tc_core, test_jwt_encode_fp, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_str, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_alg_none, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_hs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_hs384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_hs512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_change_alg, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_invalid, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_decode, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Encode");
}
