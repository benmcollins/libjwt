/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"
START_TEST(test_jwt_encode_fp)
{
	const char exp[] = "eyJhbGciOiJub25lIn0.eyJpYXQiOjE0NzU5ODA1NDUsIml"
		"zcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6IlhYWFgtWVlZW"
		"S1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.";
	char read_back[BUFSIZ];
	jwt_value_t jval;
	FILE *out;
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = fopen("test_outfile.txt", "w");
	ck_assert_ptr_nonnull(out);

	ret = jwt_encode_fp(jwt, out);
	ck_assert_int_eq(ret, 0);
	fclose(out);

	out = fopen("test_outfile.txt", "r");
	ck_assert_ptr_nonnull(out);
	ret = fread(read_back, 1, sizeof(read_back), out);
	ck_assert_int_gt(ret, 0);
	read_back[ret] = '\0';
	fclose(out);
	unlink("test_outfile.txt");

	ck_assert_str_eq(exp, read_back);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_str)
{
	const char res[] = "eyJhbGciOiJub25lIn0.eyJpYXQiOjE0NzU5ODA1NDUsIml"
		"zcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6IlhYWFgtWVlZW"
		"S1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.";
	jwt_value_t jval;
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_alg_none)
{
	const char res[] = "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ3d3cucGx1Z2dlcnM"
		"ubmwiLCJleHAiOjE0Nzc1MTQ4MTIsInN1YiI6IlBsdWdnZXJzIFNvZnR3Y"
		"XJlIn0.";
	jwt_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;
	char *out;

	SET_OPS();

	EMPTY_JWT(jwt);

	jwt_set_ADD_STR(&jval, "aud", "www.pluggers.nl");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "exp", 1477514812);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "Pluggers Software");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_hs256)
{
	const char res[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.JgSDx8Xwc6tjMDglRndhLeAbjPPrTNoK6uc_E_TDu_o";
	jwt_test_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;
	char *out;

	SET_OPS();

	CREATE_JWT(jwt, "oct_key_256.json", JWT_ALG_HS256);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);
}
END_TEST

START_TEST(test_jwt_encode_hs384)
{
	const char res[] = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.sI0hzVmaMsnfKjEGsANdMNPUfe_Pk1JPY_aixKCxVvCy25B0ADUBQdKz"
		"6VIUPmG_";
	jwt_test_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;
	char *out;

	SET_OPS();

	CREATE_JWT(jwt, "oct_key_384.json", JWT_ALG_HS384);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);
}
END_TEST

START_TEST(test_jwt_encode_hs512)
{
	const char res[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.qQ1ghQaPvzIRnzGgUPmvqEk0NlcMYjeZuna8xQLfKtZ52VHCaT-FS8T0"
		"O2O_O9NQyqnA3sNnDaSsTxq1fEuDLA";
	jwt_test_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;
	char *out;

	SET_OPS();

	CREATE_JWT(jwt, "oct_key_512.json", JWT_ALG_HS512);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);
}
END_TEST

START_TEST(test_jwt_encode_change_alg)
{
	const char res[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOj"
		"E0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJl"
		"ZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn"
		"0.qQ1ghQaPvzIRnzGgUPmvqEk0NlcMYjeZuna8xQLfKtZ52VHCaT-FS8T0"
		"O2O_O9NQyqnA3sNnDaSsTxq1fEuDLA";
	jwt_test_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret = 0;
	char *out;

	SET_OPS();

	CREATE_JWT(jwt, "oct_key_512.json", JWT_ALG_HS512);

	jwt_set_ADD_STR(&jval, "iss", "files.maclara-llc.com");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "sub", "user0");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "iat", TS_CONST);
	ret = jwt_grant_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, res);

	free(out);
}
END_TEST

START_TEST(test_jwt_encode_decode)
{
	jwt_test_auto_t *mytoken = NULL;
	jwt_auto_t *ymtoken = NULL;
	jwt_value_t jval;
	char *encoded;

	SET_OPS();

	CREATE_JWT(mytoken, "oct_key_256.json", JWT_ALG_HS256);
	jwt_set_ADD_STR(&jval, "sub", "user0");
	jwt_grant_add(mytoken, &jval);
	jwt_set_ADD_INT(&jval, "iat", 1619130517);
	jwt_grant_add(mytoken, &jval);
	jwt_set_ADD_INT(&jval, "exp", 1619216917);
	jwt_grant_add(mytoken, &jval);

	encoded = jwt_encode_str(mytoken);

	t_config.alg = JWT_ALG_HS256;
	ymtoken = jwt_verify(encoded, &t_config);
	ck_assert_ptr_nonnull(ymtoken);
        ck_assert_int_eq(jwt_error(ymtoken), 0);

	free(encoded);
}
END_TEST

START_TEST(test_jwt_encode_too_short)
{
	jwt_test_auto_t *mytoken;
	jwt_value_t jval;
	char *encoded;

	SET_OPS();

	CREATE_JWT(mytoken, "oct_key_512_bad.json", JWT_ALG_HS512);
	jwt_set_ADD_STR(&jval, "sub", "user0");
	jwt_grant_add(mytoken, &jval);
	jwt_set_ADD_INT(&jval, "iat", 1619130517);
	jwt_grant_add(mytoken, &jval);
	jwt_set_ADD_INT(&jval, "exp", 1619216917);
	jwt_grant_add(mytoken, &jval);

	encoded = jwt_encode_str(mytoken);
	ck_assert_ptr_null(encoded);
	ck_assert_int_ne(jwt_error(mytoken), 0);
	ck_assert_str_eq(jwt_error_msg(mytoken),
			 "Key too short for HS512: 256 bits");
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
	tcase_add_loop_test(tc_core, test_jwt_encode_decode, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_too_short, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Encode");
}
