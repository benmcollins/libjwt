/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_dump_fp)
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

	ret = jwt_dump_fp(jwt, out, 1);
	ck_assert_int_eq(ret, 0);

	ret = jwt_dump_fp(jwt, out, 0);
	ck_assert_int_eq(ret, 0);

	fclose(out);

        jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dump_str)
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

	out = jwt_dump_str(jwt, 1);
	ck_assert(out != NULL);

	free(out);

	out = jwt_dump_str(jwt, 0);
	ck_assert(out != NULL);

	free(out);

	jwt_free(jwt);
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Dump");

	tc_core = tcase_create("jwt_dump");

	tcase_add_test(tc_core, test_jwt_dump_fp);
	tcase_add_test(tc_core, test_jwt_dump_str);

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
