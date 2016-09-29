/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

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

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
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

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
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

START_TEST(test_jwt_rsa_dump_str)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	unsigned char rsa_key[494] = "-----BEGIN RSA PRIVATE KEY-----"
		"MIIBOgIBAAJBANHugwzNYwBmRX4HS7VumY29EdSVKIytoOgGxCBhhSJkH1GknyTo"
		"MefHUq8Z+GGB5oi0vahxiNZFhrknxxfWiSkCAwEAAQJAYJ6o3DSPUzi+1SFge/Ga"
		"ZLzXPwMjdZPYEdJDZC/eCZQ7ScesWdzyoaYeednogrDLg9xd4h+yjVAEZv4C8fwT"
		"PQIhAPl4nsCey4Cst2cgu/kYGHEA9/aWcq/PdDXlE+/BJ9VXAiEA12z9S8imO2Ob"
		"lbMdE02Tmtn4mQO04mepFIsrNP6/BX8CIQCvxa0VSs1X/Fm87/OBrtiJxoTv2VE1"
		"TpYy4xUI+K94QQIgZZqUBPBH5u7d7McjyXznRzvTEmg7IiV+C6Bv6njUI4UCIGHw"
		"tHgLQovcF+DaPC2QmsfZQ7TRCpyysT0mDSOqf9R1"
		"-----END RSA PRIVATE KEY-----";
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

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_RS256, rsa_key, sizeof(rsa_key));

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
	tcase_add_test(tc_core, test_jwt_rsa_dump_str);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
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
