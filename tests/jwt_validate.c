/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static jwt_t *jwt;

static const time_t iat = TS_CONST;
static const time_t not_before = TS_CONST + 60L;
static const time_t expires = TS_CONST + 600L;

static void __setup_jwt()
{
	EMPTY_JWT(jwt);
	jwt_add_grant(jwt, "iss", "test");
	jwt_add_grant(jwt, "sub", "user0");
	jwt_add_grants_json(jwt, "{\"aud\": [\"svc1\",\"svc2\"]}");
	jwt_add_grant_int(jwt, "iat", iat);
	jwt_add_grant_bool(jwt, "admin", 1);
}

static void __teardown_jwt()
{
	jwt_free(jwt);
	jwt = NULL;
}

#define __VAL_EQ(__v, __e, __str) do {			\
	unsigned int __r = jwt_validate(jwt, __v);	\
	char *__s;					\
	ck_assert_int_eq(__r, __e);			\
	__r = jwt_valid_get_status(__v);		\
	ck_assert_int_eq(__e, __r);			\
	__s = jwt_exception_str(__r);			\
	ck_assert_str_eq(__str, __s);			\
	jwt_free_str(__s);				\
} while(0);

START_TEST(test_jwt_validate_errno)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;
	char *exc;

	SET_OPS();

	ck_assert_ptr_nonnull(jwt);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* Validate fails with NULL jwt */
	ret = jwt_validate(NULL, jwt_valid);
	ck_assert_int_eq(ret, JWT_VALIDATION_ERROR);
	ret = jwt_valid_get_status(jwt_valid);
	ck_assert_int_eq(ret, JWT_VALIDATION_ERROR);
	exc = jwt_exception_str(ret);
	ck_assert_str_eq(exc, "general failures");
	jwt_free_str(exc);


	/* Validate fails with NULL jwt_valid */
	ret = jwt_validate(jwt, NULL);
	ck_assert_int_eq(ret, JWT_VALIDATION_ERROR);

	/* Get status fails with NULL jwt_valid */
	ck_assert_int_eq(JWT_VALIDATION_ERROR, jwt_valid_get_status(NULL));

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_algorithm)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	/* Matching algorithm is valid */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	jwt_valid_free(jwt_valid);

	/* Wrong algorithm is not valid */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_HS256);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* Starts with invalid */
	ck_assert_int_eq(JWT_VALIDATION_ERROR, jwt_valid_get_status(jwt_valid));

	__VAL_EQ(jwt_valid, JWT_VALIDATION_ALG_MISMATCH, "algorithm mismatch");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_require_grant)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;
	const char *valstr = NULL;
	int valnum = 0;

	SET_OPS();

	/* Valid when alg matches and all required grants match */
	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grant(jwt_valid, "iss", "test");
	ck_assert_int_eq(ret, 0);

	/* No duplicates */
	ret = jwt_valid_add_grant(jwt_valid, "iss", "other");
	ck_assert_int_eq(ret, EEXIST);

	/* Grant has expected value */
	valstr = jwt_valid_get_grant(jwt_valid, "iss");
	ck_assert_ptr_nonnull(valstr);
	ck_assert_str_eq(valstr, "test");

	ret = jwt_valid_add_grant_int(jwt_valid, "iat", (long)iat);
	ck_assert_int_eq(ret, 0);

	/* No duplicates for int */
	ret = jwt_valid_add_grant_int(jwt_valid, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, EEXIST);

	/* Grant has expected value */
	valnum = jwt_valid_get_grant_int(jwt_valid, "iat");
	ck_assert_int_eq(valnum, (long)iat);

	ret = jwt_valid_add_grant_bool(jwt_valid, "admin", 1);
	ck_assert_int_eq(ret, 0);

	/* No duplicates for bool */
	ret = jwt_valid_add_grant_bool(jwt_valid, "admin", 0);
	ck_assert_int_eq(ret, EEXIST);

	/* Grant has expected value */
	valnum = jwt_valid_get_grant_bool(jwt_valid, "admin");
	ck_assert_int_eq(valnum, 1);

	ret = jwt_valid_add_grants_json(jwt_valid, "{\"aud\": [\"svc1\",\"svc2\"]}");
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_nonmatch_grant)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* Invalid when required grants don't match */
	ret = jwt_valid_add_grant(jwt_valid, "iss", "wrong");
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISMATCH, "grant mismatch");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* Invalid when required grants don't match (int) */
	ret = jwt_valid_add_grant_int(jwt_valid, "iat", (long)time(NULL) + 1);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISMATCH, "grant mismatch");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* Invalid when required grants don't match (bool) */
	ret = jwt_valid_add_grant_bool(jwt_valid, "admin", 0);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISMATCH, "grant mismatch");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* Invalid when required grants don't match (json) */
	ret = jwt_valid_add_grants_json(jwt_valid, "{\"aud\": [\"svc3\",\"svc4\"]}");
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISMATCH, "grant mismatch");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_grant_bool)
{
	jwt_valid_t *jwt_valid = NULL;
	int val;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grant_bool(jwt_valid, "admin", 1);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_grant_bool(jwt_valid, "admin");
	ck_assert(val);

	ret = jwt_valid_add_grant_bool(jwt_valid, "test", 0);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_grant_bool(jwt_valid, "test");
	ck_assert(!val);

	val = jwt_valid_get_grant_bool(jwt_valid, "not found");
	ck_assert_int_eq(errno, ENOENT);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_del_grants)
{
	jwt_valid_t *jwt_valid = NULL;
	const char *val;
	const char testval[] = "testing";
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grant(jwt_valid, "iss", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_grant(jwt_valid, "other", testval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_del_grants(jwt_valid, "iss");
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_grant(jwt_valid, "iss");
	ck_assert_ptr_null(val);

	/* Delete non existent. */
	ret = jwt_valid_del_grants(jwt_valid, "iss");
	ck_assert_int_eq(ret, 0);

	/* Delete all grants. */
	ret = jwt_valid_del_grants(jwt_valid, NULL);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_grant(jwt_valid, "other");
	ck_assert_ptr_null(val);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_invalid_grant)
{
	jwt_valid_t *jwt_valid = NULL;
	const char *val;
	long valint = 0;
	long valbool = 0;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grant(jwt_valid, "iss", NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_valid_add_grant_int(jwt_valid, "", (long)time(NULL));
	ck_assert_int_eq(ret, EINVAL);

	val = jwt_valid_get_grant(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert_ptr_null(val);

	valint = jwt_valid_get_grant_int(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valint == 0);

	valbool = jwt_valid_get_grant_bool(jwt_valid, NULL);
	ck_assert_int_eq(errno, EINVAL);
	ck_assert(valbool == 0);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_missing_grant)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* JWT is invalid when required grants are not present */
	ret = jwt_valid_add_grant(jwt_valid, "np-str", "test");
	ck_assert_int_eq(ret, 0);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISSING, "grant missing");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* JWT is invalid when required grants are not present (int) */
	ret = jwt_valid_add_grant_int(jwt_valid, "np-int", 7);
	ck_assert_int_eq(ret, 0);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISSING, "grant missing");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* JWT is invalid when required grants are not present (bool) */
	ret = jwt_valid_add_grant_int(jwt_valid, "np-bool", 1);
	ck_assert_int_eq(ret, 0);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISSING, "grant missing");

	jwt_valid_del_grants(jwt_valid, NULL);

	/* JWT is invalid when required grants are not present (json) */
	ret = jwt_valid_add_grants_json(jwt_valid, "{\"np-other\": [\"foo\",\"bar\"]}");
	ck_assert_int_eq(ret, 0);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_GRANT_MISSING, "grant missing");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_not_before)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	jwt_add_grant_int(jwt, "nbf", not_before);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* JWT is invalid when now < not-before */
	ret = jwt_valid_set_now(jwt_valid, not_before - 1);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_TOO_NEW, "token future dated");

	/* JWT is valid when now >= not-before */
	ret = jwt_valid_set_now(jwt_valid, not_before);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_set_nbf_leeway)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* 0 by default */
	time_t init_nbf_leeway = jwt_valid_get_nbf_leeway(jwt_valid);
	ck_assert_int_eq(init_nbf_leeway, 0);

	/* Setting nbf_leeway */
	ret = jwt_valid_set_nbf_leeway(jwt_valid, 1);
	ck_assert_int_eq(ret, 0);

	time_t set_nbf_leeway = jwt_valid_get_nbf_leeway(jwt_valid);
	ck_assert_int_eq(set_nbf_leeway, 1);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_not_before_leeway)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	jwt_add_grant_int(jwt, "nbf", not_before);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* Setting nbf_leeway */
	ret = jwt_valid_set_nbf_leeway(jwt_valid, 10);
	ck_assert_int_eq(ret, 0);

	/* JWT is invalid when now < not-before - nbf_leeway */
	ret = jwt_valid_set_now(jwt_valid, (long)not_before - 15);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_TOO_NEW, "token future dated");

	/* JWT is valid when now >= not-before - nbf_leeway */
	ret = jwt_valid_set_now(jwt_valid, (long)not_before - 5);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_expires)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	jwt_add_grant_int(jwt, "exp", expires);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* JWT is valid when now < expires */
	ret = jwt_valid_set_now(jwt_valid, (long)expires - 1);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is invalid when now >= expires */
	ret = jwt_valid_set_now(jwt_valid, (long)expires);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_EXPIRED, "token expired");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_set_exp_leeway)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* 0 by default */
	time_t init_exp_leeway = jwt_valid_get_exp_leeway(jwt_valid);
	ck_assert_int_eq(init_exp_leeway, 0);

	/* Setting exp_leeway */
	ret = jwt_valid_set_exp_leeway(jwt_valid, 1);
	ck_assert_int_eq(ret, 0);

	time_t set_exp_leeway = jwt_valid_get_exp_leeway(jwt_valid);
	ck_assert_int_eq(set_exp_leeway, 1);

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_expires_leeway)
{
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	jwt_add_grant_int(jwt, "exp", expires);

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	/* Setting exp_leeway */
	ret = jwt_valid_set_exp_leeway(jwt_valid, 10);
	ck_assert_int_eq(ret, 0);

	/* JWT is valid when now < expires + exp_leeway */
	ret = jwt_valid_set_now(jwt_valid, (long)expires + 5);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is invalid when now >= expires + exp_leeway */
	ret = jwt_valid_set_now(jwt_valid, (long)expires + 15);
	ck_assert_int_eq(ret, 0);

	__VAL_EQ(jwt_valid, JWT_VALIDATION_EXPIRED, "token expired");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_headers)
{
	jwt_value_t jval;
	jwt_valid_t *jwt_valid = NULL;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_set_headers(jwt_valid, 1);
	ck_assert_int_eq(ret, 0);

	/* JWT is valid when iss in hdr matches iss in body */
	jwt_set_ADD_STR(&jval, "iss", "test");
	jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is invalid when iss in hdr does not match iss in body */
	jwt_header_del(jwt, "iss");
	jwt_set_ADD_STR(&jval, "iss", "wrong");
	jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_ISS_MISMATCH, "issuer mismatch");

	/* JWT is valid when checking hdr and iss not replicated */
	jwt_header_del(jwt, "iss");
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is valid when iss in hdr matches iss in body */
	jwt_set_ADD_STR(&jval, "sub", "user0");
	jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is invalid when iss in hdr does not match iss in body */
	jwt_header_del(jwt, "sub");
	jwt_set_ADD_STR(&jval, "sub", "wrong");
	jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUB_MISMATCH, "subject mismatch");

	/* JWT is valid when checking hdr and sub not replicated */
	jwt_header_del(jwt, "sub");
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is valid when checking hdr and aud matches */
        jwt_set_ADD_JSON(&jval, "{\"aud\": [\"svc1\",\"svc2\"]}");
        jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	/* JWT is invalid when checking hdr and aud does not match */
	jwt_header_del(jwt, "aud");
	jwt_set_ADD_JSON(&jval, "{\"aud\": [\"svc1\",\"svc2\",\"svc3\"]}");
	jwt_header_add(jwt, &jval);
	__VAL_EQ(jwt_valid, JWT_VALIDATION_AUD_MISMATCH, "audience mismatch");

	/* JWT is invalid when checking hdr and aud does not match */
	jwt_header_del(jwt, "aud");
	__VAL_EQ(jwt_valid, JWT_VALIDATION_SUCCESS, "success");

	jwt_valid_free(jwt_valid);
}
END_TEST

START_TEST(test_jwt_valid_grants_json)
{
	const char *json = "{\"id\":\"FVvGYTr3FhiURCFebsBOpBqTbzHdX/DvImiA2yheXr8=\","
		"\"iss\":\"localhost\",\"other\":[\"foo\",\"bar\"],"
		"\"ref\":\"385d6518-fb73-45fc-b649-0527d8576130\","
		"\"scopes\":\"storage\",\"sub\":\"user0\"}";
	jwt_valid_t *jwt_valid = NULL;
	const char *val;
	char *json_val;
	unsigned int ret = 0;

	SET_OPS();

	ret = jwt_valid_new(&jwt_valid, JWT_ALG_NONE);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grants_json(jwt_valid, json);
	ck_assert_int_eq(ret, 0);

	val = jwt_valid_get_grant(jwt_valid, "ref");
	ck_assert_ptr_nonnull(val);
	ck_assert_str_eq(val, "385d6518-fb73-45fc-b649-0527d8576130");

	json_val = jwt_valid_get_grants_json(NULL, "other");
	ck_assert_ptr_null(json_val);
	ck_assert_int_eq(errno, EINVAL);

	json_val = jwt_valid_get_grants_json(jwt_valid, "other");
	ck_assert_ptr_nonnull(json_val);
	ck_assert_str_eq(json_val, "[\"foo\",\"bar\"]");

	jwt_free_str(json_val);

	json_val = jwt_valid_get_grants_json(jwt_valid, NULL);
	ck_assert_ptr_nonnull(json_val);
	ck_assert_str_eq(json_val, json);

	jwt_free_str(json_val);

	jwt_valid_free(jwt_valid);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_validate");

	/* Run before and after each unit test. */
	tcase_add_checked_fixture(tc_core, __setup_jwt, __teardown_jwt);

	tcase_add_loop_test(tc_core, test_jwt_validate_errno, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_algorithm, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_require_grant, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_nonmatch_grant, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_invalid_grant, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_missing_grant, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_grant_bool, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_grants_json, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_del_grants, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_not_before, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_set_nbf_leeway, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_not_before_leeway, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_expires, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_set_exp_leeway, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_expires_leeway, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_valid_headers, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Validate");
}
