/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_add_grant)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	/* No duplicates */
	ret = jwt_add_grant(jwt, "iss", "other");
	ck_assert_int_eq(ret, EEXIST);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_get_grant)
{
	jwt_t *jwt = NULL;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", testval);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_grant(jwt, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, testval);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_del_grant)
{
	jwt_t *jwt = NULL;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_del_grant(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	val = jwt_get_grant(jwt, "iss");
	ck_assert(val == NULL);

	/* Delete non existent. */
	ret = jwt_del_grant(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_grant_invalid)
{
	jwt_t *jwt = NULL;
	const char *val;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_del_grant(jwt, "");
	ck_assert_int_eq(ret, EINVAL);

	val = jwt_get_grant(jwt, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(val == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_grants_json)
{
	const char *json = "{\"ref\":\"385d6518-fb73-45fc-b649-0527d8576130\""
		",\"id\":\"FVvGYTr3FhiURCFebsBOpBqTbzHdX/DvImiA2yheXr8=\","
		"\"iss\":\"localhost\",\"scopes\":\"storage\",\"sub\":"
		"\"user0\"}";
	jwt_t *jwt = NULL;
	const char *val;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grants_json(jwt, json);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_grant(jwt, "ref");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "385d6518-fb73-45fc-b649-0527d8576130");

	jwt_free(jwt);
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Grant");

	tc_core = tcase_create("jwt_grant");

	tcase_add_test(tc_core, test_jwt_add_grant);
	tcase_add_test(tc_core, test_jwt_get_grant);
	tcase_add_test(tc_core, test_jwt_del_grant);
	tcase_add_test(tc_core, test_jwt_grant_invalid);
	tcase_add_test(tc_core,test_jwt_grants_json);

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
