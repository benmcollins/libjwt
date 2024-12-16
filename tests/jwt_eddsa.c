/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static const char jwt_eddsa[] = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYX"
	"QiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6I"
	"lhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.19ip2DFFjaZ_"
	"UFVCo0OtdwuzSmOYModleJVeFcAjb_4hrAAf0pZSf8O78pivbXLJenEIsaZ9REFOauB"
	"eDxbTBw";

START_TEST(test_jwt_encode_eddsa)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_EDDSA, "eddsa_key_ed25519.pem", "eddsa_key_ed25519_pub.pem");
}
END_TEST

START_TEST(test_jwt_verify_eddsa)
{
	SET_OPS();
	__verify_jwt(jwt_eddsa, JWT_ALG_EDDSA, "eddsa_key_ed25519_pub.pem");
}
END_TEST

START_TEST(test_jwt_encode_eddsa_with_rsa)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	read_key("rsa_key_4096.pem");
	ret = jwt_set_alg(jwt, JWT_ALG_EDDSA, key, key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);
	ck_assert_int_eq(errno, EINVAL);

	jwt_free(jwt);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_eddsa");

	tcase_add_loop_test(tc_core, test_jwt_encode_eddsa, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_eddsa, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_eddsa_with_rsa, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT EdDSA Sign/Verify");
}
