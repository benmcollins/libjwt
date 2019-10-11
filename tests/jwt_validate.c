/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>

#include <jwt.h>

jwt_t *jwt = NULL;

#define TS_CONST 1570732480L
const time_t iat = TS_CONST;
const time_t not_before = TS_CONST + 60L;
const time_t expires = TS_CONST + 600L;

static void __setup_jwt()
{
	jwt_new(&jwt);
	jwt_add_grant(jwt, "iss", "test");
	jwt_add_grant_int(jwt, "iat", iat);
	jwt_add_grant_bool(jwt, "admin", 1);
	jwt_set_alg(jwt, JWT_ALG_NONE, NULL, 0);
}

static void __teardown_jwt()
{
	jwt_free(jwt);
	jwt = NULL;
}

START_TEST(test_jwt_valid)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();

	/* Matching algorithm is valid */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(ret, 1);

	jwt_valid_free(jwt_valid);

	/* Wrong algorithm is not valid */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_HS256);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(ret, 0);

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_require_grant)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();

	/* Valid when alg matches and required grants match */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant(jwt_valid, "iss", "test");
	ck_assert_int_eq(ret, 0);

	/* No duplicates */
	ret = jwt_valid_add_required_grant(jwt_valid, "iss", "other");
	ck_assert_int_eq(ret, EEXIST);

	/* No duplicates for int */
	ret = jwt_valid_add_required_grant_int(jwt_valid, "iat", (long)iat);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_required_grant_int(jwt_valid, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, EEXIST);

	/* No duplicates for bool */
	ret = jwt_valid_add_required_grant_bool(jwt_valid, "admin", 1);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_required_grant_bool(jwt_valid, "admin", 0);
	ck_assert_int_eq(ret, EEXIST);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(ret, 1);

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_require_grant_nonmatch)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();

	/* Invalid when required grants don't match */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant(jwt_valid, "iss", "wrong");
	ck_assert_int_eq(ret, 0);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(ret, 0);

	jwt_valid_del_required_grants(jwt_valid, NULL);

	/* Invalid when required grants don't match */
	ret = jwt_valid_add_required_grant_int(jwt_valid, "iat", (long)time(NULL) + 1);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(ret, 0);

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_required_grant_bool)
{
	jwt_valid_t *jwt_valid = NULL;
	int val;
	int ret = 0;

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant_bool(jwt_valid, "admin", 1);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_required_grant_bool(jwt_valid, "admin");
	ck_assert(val);

	ret = jwt_valid_add_required_grant_bool(jwt_valid, "test", 0);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_required_grant_bool(jwt_valid, "test");
	ck_assert(!val);

	val = jwt_valid_get_required_grant_bool(jwt_valid, "not found");
	ck_assert_int_eq(errno, ENOENT);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_del_grants)
{
	jwt_valid_t *jwt_valid = NULL;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant(jwt_valid, "iss", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_required_grant(jwt_valid, "other", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_del_required_grants(jwt_valid, "iss");
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_required_grant(jwt_valid, "iss");
	ck_assert(val == NULL);

	/* Delete non existent. */
	ret = jwt_valid_del_required_grants(jwt_valid, "iss");
	ck_assert_int_eq(ret, 0);

	/* Delete all grants. */
	ret = jwt_valid_del_required_grants(jwt_valid, NULL);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_required_grant(jwt_valid, "other");
	ck_assert(val == NULL);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_require_grant_invalid)
{
	jwt_valid_t *jwt_valid = NULL;
	const char *val;
	long valint = 0;
	long valbool = 0;
	int ret = 0;

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant(jwt_valid, "iss", NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_valid_add_required_grant_int(jwt_valid, "", (long)time(NULL));
	ck_assert_int_eq(ret, EINVAL);

	val = jwt_valid_get_required_grant(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(val == NULL);

	valint = jwt_valid_get_required_grant_int(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valint == 0);

	valbool = jwt_valid_get_required_grant_bool(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valbool == 0);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_missing_grants)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();

	/* JWT is invalid when required grants are not present */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_add_required_grant(jwt_valid, "sub", "test");
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_required_grant_int(jwt_valid, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(0, jwt_validate(jwt, jwt_valid));

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_not_before)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();
	jwt_add_grant_int(jwt, "nbf", not_before);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	/* JWT is invalid when now < not-before */
	ret = jwt_valid_set_now(jwt_valid, not_before - 1);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(0, jwt_validate(jwt, jwt_valid));

	/* JWT is valid when now >= not-before */
	ret = jwt_valid_set_now(jwt_valid, not_before);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(1, jwt_validate(jwt, jwt_valid));

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_expires)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	__setup_jwt();
	jwt_add_grant_int(jwt, "exp", expires);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	/* JWT is valid when now < expires */
	ret = jwt_valid_set_now(jwt_valid, (long)expires - 1);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(1, jwt_validate(jwt, jwt_valid));

	/* JWT is invalid when now >= expires */
	ret = jwt_valid_set_now(jwt_valid, (long)expires);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(0, jwt_validate(jwt, jwt_valid));

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST

START_TEST(test_jwt_valid_headers)
{
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	/* JWT is valid when iss in hdr matches iss in body */
	__setup_jwt();
	jwt_add_header(jwt, "iss", "test");

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt_valid != NULL);

	ret = jwt_valid_set_headers(jwt_valid, 1);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(1, jwt_validate(jwt, jwt_valid));

	jwt_del_headers(jwt, "iss");

	/* JWT is invalid when iss in hdr does not match iss in body */
	jwt_add_header(jwt, "iss", "wrong");

	ck_assert_int_eq(0, jwt_validate(jwt, jwt_valid));

	jwt_del_headers(jwt, "iss");

	/* JWT is valid when checking hdr, but iss not replicated */
	ck_assert_int_eq(1, jwt_validate(jwt, jwt_valid));

	jwt_valid_free(jwt_valid);
	__teardown_jwt();
}
END_TEST


#if 0
START_TEST(test_jwt_valid_grants_json)
{
	const char *json = "{\"id\":\"FVvGYTr3FhiURCFebsBOpBqTbzHdX/DvImiA2yheXr8=\","
		"\"iss\":\"localhost\",\"other\":[\"foo\",\"bar\"],"
		"\"ref\":\"385d6518-fb73-45fc-b649-0527d8576130\","
		"\"scopes\":\"storage\",\"sub\":\"user0\"}";
	jwt_t *jwt = NULL;
	const char *val;
	char *json_val;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grants_json(jwt, json);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_grant(jwt, "ref");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "385d6518-fb73-45fc-b649-0527d8576130");

	json_val = jwt_get_grants_json(NULL, "other");
	ck_assert(json_val == NULL);
	ck_assert_int_eq(errno, EINVAL);

	json_val = jwt_get_grants_json(jwt, "other");
	ck_assert(json_val != NULL);
	ck_assert_str_eq(json_val, "[\"foo\",\"bar\"]");

	jwt_free_str(json_val);

	json_val = jwt_get_grants_json(jwt, NULL);
	ck_assert(json_val != NULL);
	ck_assert_str_eq(json_val, json);

	jwt_free_str(json_val);

	jwt_free(jwt);
}
END_TEST
#endif

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Grant");

	tc_core = tcase_create("jwt_grant");

	tcase_add_test(tc_core, test_jwt_valid);
	tcase_add_test(tc_core, test_jwt_valid_require_grant);
	tcase_add_test(tc_core, test_jwt_valid_required_grant_bool);
	tcase_add_test(tc_core, test_jwt_valid_require_grant_nonmatch);
	tcase_add_test(tc_core, test_jwt_valid_del_grants);
	tcase_add_test(tc_core, test_jwt_valid_require_grant_invalid);
	tcase_add_test(tc_core, test_jwt_valid_missing_grants);
	tcase_add_test(tc_core, test_jwt_valid_not_before);
	tcase_add_test(tc_core, test_jwt_valid_expires);
	tcase_add_test(tc_core, test_jwt_valid_headers);

	tcase_set_timeout(tc_core, 30);

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
