/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"

START_TEST(new)
{
	jwt_checker_auto_t *checker = NULL;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

}
END_TEST

START_TEST(verify)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
		"XNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

static int __verify_wcb(jwt_t *jwt, jwt_config_t *config)
{
	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);

	ck_assert_str_eq(config->ctx, "testing");

	return 0;
}

START_TEST(verify_wcb)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
		"XNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_setcb(checker, __verify_wcb, "testing");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(verify_stress)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
		"XNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int i;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	for (i = 0; i < 1000; i++) {
		int ret = jwt_checker_verify(checker, token);
		ck_assert_int_eq(ret, 0);
	}
}
END_TEST

START_TEST(null_handling)
{
	jwt_checker_t *checker = NULL;
	const char *out;
	jwk_item_t *key = NULL;
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	jwt_checker_free(NULL);

	ret = jwt_checker_setkey(NULL, JWT_ALG_HS256, NULL);
	ck_assert_int_ne(ret, 0);

	/* Create and clear an error */
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, NULL);
	ck_assert_int_ne(ret, 0);
	/* Check error exists */
	ck_assert_int_ne(jwt_checker_error(checker), 0);
	out = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_ne(strlen(out), 0);
	/* Clear it */
	jwt_checker_error_clear(checker);
	/* Check that its cleared */
	ck_assert_int_eq(jwt_checker_error(checker), 0);
	out = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(strlen(out), 0);

	/* Fake it */
	key = (void *)checker;
	ret = jwt_checker_setkey(NULL, 0, key);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_error(NULL);
	ck_assert_int_ne(ret, 0);

	out = jwt_checker_error_msg(NULL);
	ck_assert_ptr_null(out);

	out = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(strlen(out), 0);

	jwt_checker_error_clear(NULL);

	ret = jwt_checker_verify(NULL, NULL);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_verify(checker, NULL);
	ck_assert_int_ne(ret, 0);
	ck_assert_int_ne(jwt_checker_error(checker), 0);

	/* Fake it */
	out = (void *)checker;
	ret = jwt_checker_verify(NULL, out);;
	ck_assert_int_ne(ret, 0);
	ck_assert_int_ne(jwt_checker_error(checker), 0);
}
END_TEST

START_TEST(verify_hs256)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
	        "0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(verify_rsapss384)
{
	jwt_checker_auto_t *checker = NULL;
	// GnuTLS created
	const char *token1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.e30.g_OJbEk"
		"tbb721dPDZ5hDZHnf8Uk6PiZ8IoatdEGxRc3GBW8xef1jRm_jZYfWh5cEz9Mg"
		"mzN0xN3q9wYCjoBrB_UUV4sonbUX4QEmUW5B5M0JJ3KyFhzJtcVrl9pVGT6ZB"
		"FLV-Pwmlus7cq73xDVNrdIX0CkZQ-3pkesiOuUsPK62cs6cQS_TrRQe58JWk0"
		"CoLIIpaiwZ56uerdPK2uAyDaxRzlVQ_2uKkLjSRCnz4eDHRYJriGtR_bfqIWo"
		"_gQHowDh_tTeGcWiMugtp9aU6_ES7VSuS7cQuH_-oYEKwnIcM4O8zV5J9EuYl"
		"JDx0M3C2E13dyUxFEKw3nGEcdiZhcA";
	// OpenSSL created
	const char *token2 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.e30.gNMKG8F"
		"GbaYNmH5CHHfr-ApOoD5AdtCyasjGaIdphyTrfBXZEqMBet3-C3-Bw1N3hPta"
		"eN-HpFj5XlDQAy3mmyO0oAiP--NHPKMo09pNNGU18BsAH5ht9SE5Y50AB8Wr1"
		"vArRZnds3MDmAVwjcG-YBAy8q8jdUP1G9DyItd32bETq-5xlixCW1Jqk8n5Px"
		"6jMalpbYIwGYYr1vcUUbwOSagVu8crtmRaXt_PSy4kUpI4sKtggIYTjoezwy5"
		"_B0Tu_cO9xgBe-uOYvJ5rEQk5jen84pBcJ5G8OLorrefX81Vw-AKdD5kdbbqh"
		"UXSooe803Mt5G2IpDHAXmOwvVBixjA";
	// JWT.io created
	const char *token3 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.e30.XZN5m3p"
		"HZnDsdRlR8bmZ1XuSqRBALy5Ikl12KtmtFSCYF22eeIJVwuk_DpKLyhZsiXF_"
		"FIQqoKU8wOO984vK1r8nlQyv_6C0TbC-fH5bjdZ8w5esBOyihEjtG5AScbjpw"
		"FYCPz_6kayusQqA_FUS_fsjHtg3gKb6viyotlMD6CCengg9aV6TyFMchBL-0_"
		"S6u-gBZC_1IJ6-ibPy8ILSVKgi6D8ucI2ZcSP79z8BZv8-HWPSJU70Ef4CEVn"
		"Owo3Grx7zAaAuzDEBELggZeW51bOypBCmmaTy3G2txeYhBE5TI88IeYOh-lrE"
		"KVQ-ZwOB8dGr0g8wbPl_i9WPdaJV7Q";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("rsa_pss_key_2048_384_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_PS384, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token3);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token2);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token1);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

static int __verify_hs256_wcb(jwt_t *jwt, jwt_config_t *config)
{
	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);
	ck_assert_int_eq(jwt_get_alg(jwt), JWT_ALG_HS256);

	if (config->ctx != NULL) {
		config->key = g_item;
		config->alg = JWT_ALG_HS256;
	} else {
		config->key = NULL;
		config->alg = JWT_ALG_HS256;
	}

	return 0;
}

START_TEST(verify_hs256_wcb)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");

	ret = jwt_checker_setcb(checker, __verify_hs256_wcb, "testing");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_setcb(checker, __verify_hs256_wcb, NULL);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);

	free_key();
}
END_TEST

START_TEST(verify_hs256_stress)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret, i;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	for (i = 0; i < 1000; i++) {
		ret = jwt_checker_verify(checker, token);
		ck_assert_int_eq(ret, 0);
	}

	free_key();
}
END_TEST

START_TEST(verify_hs256_fail)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256_issue1.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Token failed verification");

	free_key();
}
END_TEST

START_TEST(verify_hs256_fail_stress)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret, i;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	read_json("oct_key_256_issue1.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	for (i = 0; i < 1000; i++) {
		ret = jwt_checker_verify(checker, token);
		ck_assert_int_ne(ret, 0);
		ck_assert_str_eq(jwt_checker_error_msg(checker),
				 "Token failed verification");
	}

	free_key();
}
END_TEST

START_TEST(claim_str_addgetdel)
{
	const char exp[] = "{\"iss\":\"disk.swissdisk.com\"}";
	jwt_checker_auto_t *checker = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "iss", "disk.swissdisk.com");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "aud", "public");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "aud", "private");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_STR(&jval, "aud", "employees");
	jval.replace = 1;
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "aud");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "employees");

	jwt_set_GET_INT(&jval, "aud");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_BOOL(&jval, "aud");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_checker_claim_del(checker, "aud");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_STR(&jval, "aud");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	jwt_set_GET_JSON(&jval, NULL);
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.json_val, exp);
	free(jval.json_val);
}
END_TEST

START_TEST(claim_int_addgetdel)
{
	const char exp[] = "{\"nbf\":1475980545}";
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "nbf", TS_CONST);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST + 360);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_INT(&jval, "exp", TS_CONST + 480);
	jval.replace = 1;
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "exp");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jval.int_val, TS_CONST + 480);

	jwt_set_GET_STR(&jval, "exp");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_BOOL(&jval, "exp");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_checker_claim_del(checker, "exp");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_INT(&jval, "exp");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	jwt_set_GET_JSON(&jval, NULL);
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.json_val, exp);
	free(jval.json_val);
}
END_TEST

START_TEST(claim_bool_addgetdel)
{
	const char exp[] = "{\"admin\":true}";
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "admin", 1);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "sudo", 1);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_BOOL(&jval, "sudo", 0);
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_BOOL(&jval, "sudo", 0);
	jval.replace = 1;
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "sudo");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_int_eq(jval.bool_val, 0);

	jwt_set_GET_STR(&jval, "sudo");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_INT(&jval, "sudo");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_checker_claim_del(checker, "sudo");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_BOOL(&jval, "sudo");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	jwt_set_GET_JSON(&jval, NULL);
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.json_val, exp);
	free(jval.json_val);
}
END_TEST

START_TEST(claim_json_addgetdel)
{
	const char exp[] = "{\"rooms\":[\"office\",\"war-room\"]}";
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_JSON(&jval, "rooms",
			 "[\"office\",\"war-room\"]");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "rooms");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "[\"office\",\"war-room\"]");
	free(jval.json_val);

	jwt_set_ADD_JSON(&jval, "buildings",
			 "{\"main\":\"dallas\",\"accounting\":\"houston\"}");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_JSON(&jval, "buildings", "{\"hq\": 0}");
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_EXIST);

	jwt_set_ADD_JSON(&jval, "buildings", "{\"hq\": 1}");
	jval.replace = 1;
	ret = jwt_checker_claim_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "buildings");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "{\"hq\":1}");
	free(jval.json_val);

	jwt_set_GET_STR(&jval, "buildings");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	jwt_set_GET_INT(&jval, "buildings");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_TYPE);

	ret = jwt_checker_claim_del(checker, "buildings");
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, "buildings");
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);

	jwt_set_GET_JSON(&jval, NULL);
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.json_val, exp);
	free(jval.json_val);
}

START_TEST(header_str_addgetdel)
{
	const char exp[] = "{}";
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setclaims(checker, JWT_CLAIM_NONE);
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "typ", "Custom");
	ret = jwt_checker_header_add(checker, &jval);
	ck_assert_int_eq(ret, 0);

	jwt_set_GET_JSON(&jval, NULL);
	ret = jwt_checker_claim_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.json_val, exp);
	free(jval.json_val);

	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_checker_header_get(checker, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "Custom");

	ret = jwt_checker_header_del(checker, "typ");

	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_checker_header_get(checker, &jval);
	ck_assert_int_eq(ret, JWT_VALUE_ERR_NOEXIST);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("New");
	tcase_add_loop_test(tc_core, new, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Verify");
	tcase_add_loop_test(tc_core, verify, 0, i);
	tcase_add_loop_test(tc_core, verify_rsapss384, 0, i);
	tcase_add_loop_test(tc_core, verify_wcb, 0, i);
	tcase_add_loop_test(tc_core, verify_stress, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Error Handling");
	tcase_add_loop_test(tc_core, null_handling, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("HS256 Key Verify");
	tcase_add_loop_test(tc_core, verify_hs256, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_wcb, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_stress, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_fail, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_fail_stress, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Claims AddGetDel");
	tcase_add_loop_test(tc_core, claim_str_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_int_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_bool_addgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_json_addgetdel, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Header AddGetDel");
	/* All of the code paths for str/int/bool/json have been covered. We
	 * just run this to ensure add/get/del works on headers */
	tcase_add_loop_test(tc_core, header_str_addgetdel, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Checker");
}
