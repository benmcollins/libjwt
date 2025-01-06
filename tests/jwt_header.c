/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwt_add_header)
{
	jwt_auto_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	/* No duplicates */
	ret = jwt_add_header(jwt, "iss", "other");
	ck_assert_int_eq(ret, EEXIST);

	/* No duplicates for int */
	ret = jwt_add_header_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_header_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, EEXIST);
}
END_TEST

START_TEST(test_jwt_get_header)
{
	jwt_auto_t *jwt = NULL;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header(jwt, "iss", testval);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header(jwt, "iss");
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, testval);
}
END_TEST

START_TEST(test_jwt_add_header_int)
{
	jwt_auto_t *jwt = NULL;
	long val;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header_int(jwt, "int", 1);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header_int(jwt, "int");
	ck_assert(val);

	val = jwt_get_header_int(jwt, "not found");
	ck_assert_int_eq(errno, ENOENT);
}
END_TEST

START_TEST(test_jwt_add_header_bool)
{
	jwt_auto_t *jwt = NULL;
	int val;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header_bool(jwt, "admin", 1);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header_bool(jwt, "admin");
	ck_assert(val);

	ret = jwt_add_header_bool(jwt, "test", 0);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header_bool(jwt, "test");
	ck_assert(!val);

	val = jwt_get_header_bool(jwt, "not found");
	ck_assert_int_eq(errno, ENOENT);
}
END_TEST

START_TEST(test_jwt_del_headers)
{
	jwt_auto_t *jwt = NULL;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header(jwt, "iss", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_header(jwt, "other", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_del_headers(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header(jwt, "iss");
	ck_assert_ptr_null(val);

	/* Delete non existent. */
	ret = jwt_del_headers(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	/* Delete all headers. */
	ret = jwt_del_headers(jwt, NULL);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header(jwt, "other");
	ck_assert_ptr_null(val);
}
END_TEST

START_TEST(test_jwt_header_invalid)
{
	jwt_auto_t *jwt = NULL;
	const char *val;
	long valint = 0;
	int valbool = 0;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_header(jwt, "iss", NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_add_header_int(jwt, "", (long)time(NULL));
	ck_assert_int_eq(ret, EINVAL);

	val = jwt_get_header(jwt, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert_ptr_null(val);

	valint = jwt_get_header_int(jwt, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valint == 0);

	valbool = jwt_get_header_bool(jwt, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valbool == 0);
}
END_TEST

START_TEST(test_jwt_headers_json)
{
	const char *json = "{\"id\":\"FVvGYTr3FhiURCFebsBOpBqTbzHdX/DvImiA2yheXr8=\","
		"\"iss\":\"localhost\",\"other\":[\"foo\",\"bar\"],"
		"\"ref\":\"385d6518-fb73-45fc-b649-0527d8576130\","
		"\"scopes\":\"storage\",\"sub\":\"user0\"}";
	jwt_auto_t *jwt = NULL;
	const char *val;
	char *json_val;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	ret = jwt_add_headers_json(jwt, json);
	ck_assert_int_eq(ret, 0);

	val = jwt_get_header(jwt, "ref");
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, "385d6518-fb73-45fc-b649-0527d8576130");

	json_val = jwt_get_headers_json(NULL, "other");
	ck_assert_ptr_null(json_val);
	ck_assert_int_eq(errno, EINVAL);

	json_val = jwt_get_headers_json(jwt, "other");
	ck_assert_ptr_nonnull(json_val);
	ck_assert_str_eq(json_val, "[\"foo\",\"bar\"]");

	jwt_free_str(json_val);

	json_val = jwt_get_headers_json(jwt, NULL);
	ck_assert_ptr_nonnull(json_val);
	ck_assert_str_eq(json_val, json);

	jwt_free_str(json_val);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_header");

	tcase_add_loop_test(tc_core, test_jwt_add_header, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_add_header_int, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_add_header_bool, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_get_header, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_del_headers, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_header_invalid, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_headers_json, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Header");
}
