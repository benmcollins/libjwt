/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static const char jwt_eddsa[] = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpY"
	"XQiOjE3MzYxMjA1OTIsImlzcyI6ImRpc2suc3dpc3NkaXNrLmNvbSIsInN1YiI6InV"
	"zZXIwIn0.m28yyGiulqE9CUbZ64oSlec7TglR6DvVWohayJvJsJzk65RLx99gycRig"
	"aYjKKNe0e0Fff3BsIAlh3A-ptkmAg";

START_TEST(test_jwt_encode_eddsa)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_EDDSA, "eddsa_key_ed25519.json",
		       "eddsa_key_ed25519_pub.json");
}
END_TEST

START_TEST(test_jwt_verify_eddsa)
{
	SET_OPS();
	__verify_jwt(jwt_eddsa, JWT_ALG_EDDSA, "eddsa_key_ed25519_pub.json");
}
END_TEST

START_TEST(test_jwt_encode_eddsa_with_rsa)
{
	JWT_CONFIG_DECLARE(config);
	jwt_test_auto_t *jwt = NULL;

	SET_OPS();

	read_key("rsa_key_4096.json");
	config.alg = JWT_ALG_EDDSA;
	config.jw_key = g_item;
	jwt = jwt_create(&config);
	ck_assert_int_ne(jwt_error(jwt), 0);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_str_eq(jwt_error_msg(jwt),
			 "Config alg does not match key alg");
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

int main(void)
{
	JWT_TEST_MAIN("LibJWT EdDSA Sign/Verify");
}
