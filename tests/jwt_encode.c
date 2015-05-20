/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_encode_fp)
{
	FILE *out;
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	out = fopen("/dev/null", "w");
	ck_assert(out != NULL);

	ret = jwt_encode_fp(jwt, out);
	ck_assert_int_eq(ret, 0);

	fclose(out);

        jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_str)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs256)
{
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS256, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs384)
{
	unsigned char key384[48] = "aaaabbbbccccddddeeeeffffgggghhhh"
				   "iiiijjjjkkkkllll";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS384, key384, sizeof(key384));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs512)
{
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_change_alg)
{
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, NULL, 0);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_invalid)
{
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, key512, 32);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_HS256, key512, 64);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_HS384, key512, 16);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_HS512, NULL, 64);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_set_alg(jwt, JWT_ALG_NONE, key512, sizeof(key512));
	ck_assert_int_eq(ret, EINVAL);

	/* Set a value that will never happen. */
	ret = jwt_set_alg(jwt, 999, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);

	jwt_free(jwt);
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Encode");

	tc_core = tcase_create("jwt_encode");

	tcase_add_test(tc_core, test_jwt_encode_fp);
	tcase_add_test(tc_core, test_jwt_encode_str);
	tcase_add_test(tc_core, test_jwt_encode_hs256);
	tcase_add_test(tc_core, test_jwt_encode_hs384);
	tcase_add_test(tc_core, test_jwt_encode_hs512);
	tcase_add_test(tc_core, test_jwt_encode_change_alg);
	tcase_add_test(tc_core, test_jwt_encode_invalid);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = libjwt_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
