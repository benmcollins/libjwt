/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

/* NOTE: ES signing will generate a different signature every time, so can't
 * be simply string compared for verification like we do with RS. */

static const char jwt_es256[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQ"
	"iOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZiI6Ilh"
	"YWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.IONoUPo6QhHwcx1"
	"N1TD4DnrjvmB-9lSX6qrn_WPrh3DBum-qKP66MIF9tgymy7hCoU6dvUW8zKK0AyVH3iD"
	"1uA";

static const char jwt_es384[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpYXQ"
	"iOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYLVl"
	"ZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.p6McjolhuIqel0DWaI2OrD"
	"oRYcxgSMnGFirdKT5jXpe9L801HBkouKBJSae8F7LLFUKiE2VVX_514WzkuExLQs2eB1"
	"L2Qahid5VFOK3hc7HcBL-rcCXa8d2tf_MudyrM";

static const char jwt_es512[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpYXQ"
	"iOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYLVl"
	"ZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.Abs-SriTqd9NAO-bJb-B3U"
	"zF1W8JmoutfHQpMqJnkPHyasVVuKN-I-6RibSv-qxgTxuzlo0u5dCt4mOw7w8mgEnMAS"
	"zsjm-NlOPUBjIUD9T592lse9OOF6TjPOQbijqeMc6qFZ8q5YhxvxBXHO6PuImkJpEWj4"
	"Zda8lNTxqHol7vorg9";

static const char jwt_es_invalid[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQ"
	"iOjE0NzU5ODA1IAmCornholio6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYLVl"
	"PN9G9tV75ylfWvcwkF20bQA9m1vDbUIl8PIK8Q";

START_TEST(test_jwt_encode_es256)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_ES256, "ec_key_prime256v1.pem",
		       "ec_key_prime256v1_pub.pem");
}
END_TEST

START_TEST(test_jwt_verify_es256)
{
	SET_OPS();
	__verify_jwt(jwt_es256, JWT_ALG_ES256, "ec_key_prime256v1_pub.pem");
}
END_TEST

START_TEST(test_jwt_encode_es384)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_ES384, "ec_key_secp384r1.pem", "ec_key_secp384r1_pub.pem");
}
END_TEST

START_TEST(test_jwt_verify_es384)
{
	SET_OPS();
	__verify_jwt(jwt_es384, JWT_ALG_ES384, "ec_key_secp384r1_pub.pem");
}
END_TEST

START_TEST(test_jwt_encode_es512)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_ES512, "ec_key_secp521r1.pem", "ec_key_secp521r1_pub.pem");
}
END_TEST

START_TEST(test_jwt_verify_es512)
{
	SET_OPS();
	__verify_jwt(jwt_es512, JWT_ALG_ES512, "ec_key_secp521r1_pub.pem");
}
END_TEST

START_TEST(test_jwt_encode_ec_with_rsa)
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
	ret = jwt_set_alg(jwt, JWT_ALG_ES384, t_config.key, t_config.key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);
	ck_assert_int_eq(errno, EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_verify_invalid_token)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	read_key("ec_key_secp384r1.pem");
	ret = jwt_verify(&jwt, jwt_es_invalid, &t_config);
	free_key();
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	read_key("ec_key_secp384r1.pem");
	ret = jwt_verify(&jwt, jwt_es256, &t_config);
	free_key();
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	read_key("ec_key_secp521r1_pub.pem");
	ret = jwt_verify(&jwt, jwt_es256, &t_config);
	free_key();
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert_file)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	read_key("ec_key_invalid_pub.pem");
	ret = jwt_verify(&jwt, jwt_es256, &t_config);
	free_key();
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_encode_invalid_key)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out = NULL;

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

	read_key("ec_key_invalid.pem");
	ret = jwt_set_alg(jwt, JWT_ALG_ES512, t_config.key, t_config.key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);

	jwt_free(jwt);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_ec");

	tcase_add_loop_test(tc_core, test_jwt_encode_es256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_es256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_es384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_es384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_es512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_es512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_ec_with_rsa, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_token, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_alg, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_cert, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_cert_file, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_invalid_key, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT EC Sign/Verify");
}
