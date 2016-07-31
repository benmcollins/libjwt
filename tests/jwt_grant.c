/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <check.h>

#include <jwt.h>

#define _assert_json_eq_flags (JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY)
#define assert_json_eq(X, Y) do {					\
		char *X_str = json_dumps((X), _assert_json_eq_flags);	\
		char *Y_str = json_dumps((Y), _assert_json_eq_flags);	\
									\
		ck_assert_str_eq(X_str, Y_str);				\
									\
		free(X_str);						\
		free(Y_str);						\
	} while (0)

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

START_TEST(test_jwt_grant_json)
{
	jwt_t *jwt = NULL;
	json_t *testintval, *testobjval;
	const json_t *retintval, *retobjval;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	testintval = json_integer(42);
	ck_assert(testintval != NULL);
	testobjval = json_loads("{\"quux\": \"foobar\", \"baz\": 21}",
				JSON_REJECT_DUPLICATES, NULL);
	ck_assert(testobjval != NULL);

	ret = jwt_add_grant_json(jwt, "foo", testintval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_json(jwt, "bar", testobjval);
	ck_assert_int_eq(ret, 0);
	json_decref(testobjval);

	retintval = jwt_get_grant_json(jwt, "foo");
	ck_assert(retintval != NULL);
	assert_json_eq(testintval, retintval);

	retobjval = jwt_get_grant_json(jwt, "bar");
	ck_assert(retobjval != NULL);
	assert_json_eq(testobjval, retobjval);

	json_decref(testintval);
	json_decref(testobjval);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_replace_grants)
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

	ret = jwt_replace_grants(jwt, json);
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
	tcase_add_test(tc_core, test_jwt_grant_json);
	tcase_add_test(tc_core, test_jwt_grant_invalid);
	tcase_add_test(tc_core,test_jwt_replace_grants);

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
