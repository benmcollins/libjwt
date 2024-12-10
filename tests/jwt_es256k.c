/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static const char jwt_es256k[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQ"
	"iOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6Ilh"
	"YWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.IONoUPo6QhHwcx1"
	"N1TD4DnrjvmB-9lSX6qrn_WPrh3DBum-qKP66MIF9tgymy7hCoU6dvUW8zKK0AyVH3iD"
	"1uA";

START_TEST(test_jwt_encode_es256k)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_ES256K, "ec_key_secp256k1.pem", "ec_key_secp256k1-pub.pem");
}
END_TEST

START_TEST(test_jwt_verify_es256k)
{
	SET_OPS();
	__verify_jwt(jwt_es256k, JWT_ALG_ES256K, "ec_key_secp256k1-pub.pem");
}
END_TEST

START_TEST(test_jwt_encode_es256k_with_ec)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ALLOC_JWT(&jwt);

	read_key("ec_key_prime256v1.pem");

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_ES256K, key, key_len);
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
	int i = ARRAY_SIZE(jwt_test_ops) - 1;

	s = suite_create(title);

	tc_core = tcase_create("jwt_es256k");

	tcase_add_loop_test(tc_core, test_jwt_encode_es256k, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_es256k, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_es256k_with_ec, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT ES256K Sign/Verify");
}
