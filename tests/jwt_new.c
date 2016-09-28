/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_new)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dup)
{
	jwt_t *jwt = NULL, *new = NULL;
	int ret = 0;
	const char *val = NULL;
	time_t now;
	long valint;

	new = jwt_dup(NULL);
	ck_assert(new == NULL);

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert(new != NULL);

	val = jwt_get_grant(new, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "test");

	now = time(NULL);
	ret = jwt_add_grant_int(jwt, "iat", (long)now);
	ck_assert_int_eq(ret, 0);

	valint = jwt_get_grant_int(jwt, "iat");
	ck_assert(((long)now) == valint);

	jwt_free(new);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dup_signed)
{
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt = NULL, *new = NULL;
	int ret = 0;
	const char *val = NULL;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS256, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert(new != NULL);

	val = jwt_get_grant(new, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "test");

	jwt_free(new);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dup_signed_rsa)
{
	unsigned char rsa_key[494] = "-----BEGIN RSA PRIVATE KEY-----"
		"MIIBOgIBAAJBANHugwzNYwBmRX4HS7VumY29EdSVKIytoOgGxCBhhSJkH1GknyTo"
		"MefHUq8Z+GGB5oi0vahxiNZFhrknxxfWiSkCAwEAAQJAYJ6o3DSPUzi+1SFge/Ga"
		"ZLzXPwMjdZPYEdJDZC/eCZQ7ScesWdzyoaYeednogrDLg9xd4h+yjVAEZv4C8fwT"
		"PQIhAPl4nsCey4Cst2cgu/kYGHEA9/aWcq/PdDXlE+/BJ9VXAiEA12z9S8imO2Ob"
		"lbMdE02Tmtn4mQO04mepFIsrNP6/BX8CIQCvxa0VSs1X/Fm87/OBrtiJxoTv2VE1"
		"TpYy4xUI+K94QQIgZZqUBPBH5u7d7McjyXznRzvTEmg7IiV+C6Bv6njUI4UCIGHw"
		"tHgLQovcF+DaPC2QmsfZQ7TRCpyysT0mDSOqf9R1"
		"-----END RSA PRIVATE KEY-----";
	jwt_t *jwt = NULL, *new = NULL;
	jwt_alg_t alg;
	int ret = 0;
	const char *val = NULL;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_RS256, rsa_key, sizeof(rsa_key));
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert(new != NULL);

	val = jwt_get_grant(new, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "test");

	alg = jwt_get_alg(jwt);
	ck_assert(alg == JWT_ALG_RS256);

	jwt_free(new);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJmaWxlcy5jeXBo"
				 "cmUuY29tIiwic3ViIjoidXNlcjAifQ.";
	jwt_alg_t alg;
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg == JWT_ALG_NONE);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_final_dot)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_alg)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIQUhBSCJ9."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_typ)
{
	const char token[] = "eyJ0eXAiOiJBTEwiLCJhbGciOiJIUzI1NiJ9."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_head)
{
	const char token[] = "yJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_alg_none_with_key)
{
	const char token[] = "eyJhbGciOiJub25lIn0."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, (const unsigned char *)"key", 3);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_body)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
				 "eyJpc3MiOiJmaWxlcy5jeBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs256)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
				 "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
				 "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = JWT_ALG_HS256);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs384)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
				 "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
				 "3ViIjoidXNlcjAifQ.xqea3OVgPEMxsCgyikr"
				 "R3gGv4H2yqMyXMm7xhOlQWpA-NpT6n2a1d7TD"
				 "GgU6LOe4";
	const unsigned char key384[48] = "aaaabbbbccccddddeeeeffffg"
					 "ggghhhhiiiijjjjkkkkllll";
	jwt_alg_t alg;
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, key384, sizeof(key384));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = JWT_ALG_HS384);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs512)
{
		const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3Mi"
				 "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
				 "Q.u-4XQB1xlYV8SgAnKBof8fOWOtfyNtc1ytTlc_vHo0U"
				 "lh5uGT238te6kSacnVzBbC6qwzVMT1806oa1Y8_8EOg";
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt;
	jwt_alg_t alg;
		int ret;

	ret = jwt_decode(&jwt, token, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = JWT_ALG_HS512);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_rs256)
{
	const char token[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyaWdodF90"
		"b19pbnZva2UiOlsiZ2VuaXZpLm9yZy8iXSwiaXNzIjoiZ2VuaXZpLm9yZyIsImRldm"
		"ljZV9jZXJ0IjoiTUlJQjh6Q0NBVndDQVFFd0RRWUpLb1pJaHZjTkFRRUxCUUF3UWpF"
		"TE1Ba0dBMVVFQmhNQ1ZWTXhEekFOQmdOVkJBZ01Cazl5WldkdmJqRVJNQThHQTFVRU"
		"J3d0lVRzl5ZEd4aGJtUXhEekFOQmdOVkJBb01Ca2RGVGtsV1NUQWVGdzB4TlRFeE1q"
		"Y3lNekUwTlRKYUZ3MHhOakV4TWpZeU16RTBOVEphTUVJeEN6QUpCZ05WQkFZVEFsVl"
		"RNUTh3RFFZRFZRUUlEQVpQY21WbmIyNHhFVEFQQmdOVkJBY01DRkJ2Y25Sc1lXNWtN"
		"UTh3RFFZRFZRUUtEQVpIUlU1SlZra3dnWjh3RFFZSktvWklodmNOQVFFQkJRQURnWT"
		"BBTUlHSkFvR0JBSnR2aU04QVJJckZxdVBjMG15QjlCdUY5TWRrQS8yU2F0cWJaTVdl"
		"VE9VSkhHcmpCREVFTUxRN3prOEF5Qm1pN1JxdVlZWnM2N1N5TGh5bFZHS2g2c0pBbG"
		"VjeGJIVXdqN2NaU1MxYm1LTWplNkw2MWdLd3hCbTJOSUZVMWNWbDJqSmxUYVU5Vllo"
		"TTR4azU3eWoyOG5rTnhTWVdQMXZiRlgyTkRYMmlIN2I1QWdNQkFBRXdEUVlKS29aSW"
		"h2Y05BUUVMQlFBRGdZRUFoYnFWcjlFLzBNNzI5bmM2REkrcWdxc1JTTWZveXZBM0Nt"
		"bi9FQ3hsMXliR2t1ek83c0I4ZkdqZ01ROXp6Y2I2cTF1UDN3R2pQaW9xTXltaVlZal"
		"VtQ1R2emR2UkJaKzZTRGpyWmZ3VXVZZXhpS3FJOUFQNlhLYUhsQUwxNCtySys2SE40"
		"dUlrWmNJelB3U01IaWgxYnNUUnB5WTVaM0NVRGNESmtZdFZiWXM9IiwidmFsaWRpdH"
		"kiOnsic3RhcnQiOjE0NDg2ODM3NDIsInN0b3AiOjE0ODAyMTk3NDJ9LCJyaWdodF90"
		"b19yZWdpc3RlciI6WyJnZW5pdmkub3JnLyJdLCJjcmVhdGVfdGltZXN0YW1wIjoxND"
		"Q4NjgzNzQyLCJpZCI6Inh4eCJ9.OPRklok0vZDNMHwwpOVx7lq8lDU0ukXFOAZsYBq"
		"UbD6ydy4yq-EZoFl9unTm4yQzZ9z-s31sCZyC5-qnQgpZl85oloqJA4gD0E1c4JDMR"
		"f0-arRUlCsMW74SWMRj3zTDTItc2D-R4Nhk-D_f1ZqkadhYiYFyKRcw_vhJ03OZowQ";
	unsigned char key512[] = "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDg5A1uZ5F36vQEYbMWCV4wY4OV"
		"micYWEjjl/8YPA01tsz4x68i/NnlMNalqpGCIZ0AwqGI5DZAWWoR400L3SAmYD6s"
		"Wj2L9ViIAPk3ceDU8olYrf/Nwj78wVoG7qqNLgMoBNM584nlY4jy8zJ0Ka9WFBS2"
		"aDtB3Aulc1Q8ZfhuewIDAQAB\n"
		"-----END PUBLIC KEY-----";

	jwt_t *jwt;
	jwt_alg_t alg;
	int ret;

	ret = jwt_decode(&jwt, token, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg = JWT_ALG_RS256);

	jwt_free(jwt);
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT New");

	tc_core = tcase_create("jwt_new");
	tcase_add_test(tc_core, test_jwt_new);
	tcase_add_test(tc_core, test_jwt_dup);
	tcase_add_test(tc_core, test_jwt_dup_signed);
	tcase_add_test(tc_core, test_jwt_dup_signed_rsa);
	tcase_add_test(tc_core, test_jwt_decode);
	tcase_add_test(tc_core, test_jwt_decode_invalid_alg);
	tcase_add_test(tc_core, test_jwt_decode_invalid_typ);
	tcase_add_test(tc_core, test_jwt_decode_invalid_head);
	tcase_add_test(tc_core, test_jwt_decode_alg_none_with_key);
	tcase_add_test(tc_core, test_jwt_decode_invalid_body);
	tcase_add_test(tc_core, test_jwt_decode_invalid_final_dot);
	tcase_add_test(tc_core, test_jwt_decode_hs256);
	tcase_add_test(tc_core, test_jwt_decode_hs384);
	tcase_add_test(tc_core, test_jwt_decode_hs512);
	tcase_add_test(tc_core, test_jwt_decode_rs256);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
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
