/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwt_grant_add)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", "test");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	/* No duplicates */
	jwt_set_ADD_STR(&jval, "iss", "other");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	/* No duplicates for int */
	jwt_set_ADD_INT(&jval, "iat", (long)time(NULL));
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", (long)time(NULL));
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);
}
END_TEST

START_TEST(test_jwt_grant_get)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", testval);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "iss");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.str_val;
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, testval);
}
END_TEST

START_TEST(test_jwt_grant_add_int)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_INT(&jval, "int", 1);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "int");
	ret = jwt_grant_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jval.int_val, 1);

	jwt_set_GET_INT(&jval, "not found");
	ret = jwt_grant_get(jwt, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);
}
END_TEST

START_TEST(test_jwt_grant_add_bool)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	int val;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_BOOL(&jval, "admin", 1);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "admin");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.bool_val;
	ck_assert(val);

	jwt_set_ADD_BOOL(&jval, "test", 0);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "test");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.bool_val;
	ck_assert(!val);

	jwt_set_GET_BOOL(&jval, "not found");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.bool_val;
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);
}
END_TEST

START_TEST(test_jwt_grant_del)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	const char *val;
	const char testval[] = "testing";
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", testval);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "other", testval);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_grant_del(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "iss");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.str_val;
	ck_assert_ptr_null(val);

	/* Delete non existent. */
	ret = jwt_grant_del(jwt, "iss");
	ck_assert_int_eq(ret, 0);

	/* Delete all grants. */
	ret = jwt_grant_del(jwt, NULL);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "other");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.str_val;
	ck_assert_ptr_null(val);
}
END_TEST

START_TEST(test_jwt_grant_invalid)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	const char *val;
	long valint = 0;
	int valbool = 0;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", NULL);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);

	jwt_set_ADD_INT(&jval, "", (long)time(NULL));
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);

	jwt_set_GET_STR(&jval, NULL);
	ret = jwt_grant_get(jwt, &jval);
	val = jval.str_val;
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);
	ck_assert_ptr_null(val);

	jwt_set_GET_INT(&jval, NULL);
	ret = jwt_grant_get(jwt, &jval);
	valint = jval.int_val;
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);
	ck_assert(valint == 0);

	jwt_set_GET_BOOL(&jval, NULL);
	ret = jwt_grant_get(jwt, &jval);
	valbool = jval.bool_val;
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);
	ck_assert(valbool == 0);
}
END_TEST

START_TEST(test_jwt_grants_json)
{
	char *json = "{\"id\":\"FVvGYTr3FhiURCFebsBOpBqTbzHdX/DvImiA2yheXr8=\","
		"\"iss\":\"localhost\",\"other\":[\"foo\",\"bar\"],"
		"\"ref\":\"385d6518-fb73-45fc-b649-0527d8576130\","
		"\"scopes\":\"storage\",\"sub\":\"user0\"}";
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	const char *val;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_JSON(&jval, NULL, json);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "ref");
	ret = jwt_grant_get(jwt, &jval);
	val = jval.str_val;
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, "385d6518-fb73-45fc-b649-0527d8576130");

	jwt_set_GET_JSON(&jval, "other");
	ret = jwt_grant_get(NULL, &jval);
	ck_assert_ptr_null(jval.json_val);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);

	jwt_set_GET_JSON(&jval, "other");
	ret = jwt_grant_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "[\"foo\",\"bar\"]");

	free(jval.json_val);

	jwt_set_GET_JSON(&jval, "other");
	ret = jwt_grant_get(jwt, NULL);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_INVALID);

	free(jval.json_val);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_grant");

	tcase_add_loop_test(tc_core, test_jwt_grant_add, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grant_add_int, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grant_add_bool, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grant_get, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grant_del, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grant_invalid, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_grants_json, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Grant");
}
