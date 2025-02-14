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

START_TEST(alg_none_with_sig)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
		"XNrLnN3aXNzZGlzay5jb20ifQ.XNrLnN3aXNzZGlzay5jb20ifQ";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"JWT has signature block, but no alg set");
}
END_TEST

START_TEST(bad_alg)
{
	const char token[] = "eyJhbGciOiJmb28ifQo.e30K.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

START_TEST(no_alg)
{
	const char token[] = "eyJub3RhbGciOiJmb28ifQo.e30K.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

START_TEST(no_first_dot)
{
	const char token[] = "eyJub3RhbGciOiJmb28ifQo";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

START_TEST(no_second_dot)
{
	const char token[] = "eyJub3RhbGciOiJmb28ifQo.e30K";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
}
END_TEST

START_TEST(verify_bad_header)
{
	const char token[] = "eyJhbGcOiJub25lIn0.eyJpc3MiOiJka"
	        "XNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Error parsing header");
}
END_TEST

START_TEST(verify_bad_payload)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
	        "XNrLnN3aXNzZGlzay5jb0ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Error parsing payload");
}
END_TEST

static int __verify_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_error_t err;
	jwt_value_t jval;

	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);

	jwt_set_GET_STR(&jval, "alg");
        err = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(err, JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(jval.error, JWT_VALUE_ERR_NONE);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "none");

	jwt_set_GET_INT(&jval, "iat");
	err = jwt_claim_get(jwt, &jval);
	ck_assert_int_eq(err, JWT_VALUE_ERR_NOEXIST);
	ck_assert_int_eq(jval.error, JWT_VALUE_ERR_NOEXIST);
	ck_assert_int_eq(jval.int_val, 0);

	err = jwt_header_del(jwt, "alg");
	ck_assert_int_eq(err, JWT_VALUE_ERR_NONE);

	err = jwt_claim_del(jwt, "iat");
	ck_assert_int_eq(err, JWT_VALUE_ERR_NONE);

	ck_assert_str_eq(config->ctx, "testing");

	return 0;
}

START_TEST(verify_wcb)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJkaXNrLnN3aXNzZGlz"
		"ay5jb20iLCJhdWQiOiJwdWJsaWMiLCJzdWIiOiJteS1mcmllbmQifQ.";
	jwt_checker_auto_t *checker = NULL;
	const char *ctx;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_SUB, "my-friend");
        ck_assert_int_eq(ret, 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_AUD, "public");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_ISS, "disk.swissdisk.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_setcb(checker, __verify_wcb, "testing");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);

	ctx = jwt_checker_getctx(checker);
	ck_assert_ptr_nonnull(ctx);
	ck_assert_str_eq(ctx, "testing");
}
END_TEST

START_TEST(verify_stress)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJkaXNrLnN3aXNzZGlz"
		"ay5jb20iLCJhdWQiOiJwdWJsaWMiLCJzdWIiOiJteS1mcmllbmQifQ.";
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

	out = jwt_checker_claim_get(checker, JWT_CLAIM_IAT);
	ck_assert_ptr_null(out);
	ret = jwt_checker_claim_set(checker, JWT_CLAIM_IAT, "foo");
	ck_assert_int_ne(ret, 0);
	ret = jwt_checker_claim_del(checker, JWT_CLAIM_IAT);
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_time_leeway(NULL, JWT_CLAIM_IAT, 0);
	ck_assert_int_ne(ret, 0);
	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_IAT, 0);

	/* Some alg mismatches */
	read_json("eddsa_key_ed25519_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_NONE, g_item);
	ck_assert_int_ne(ret, 0);

	jwt_checker_error_clear(checker);

	read_json("oct_key_256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_ES256, g_item);
	ck_assert_int_ne(ret, 0);

	/* Callbacks */
	ck_assert_int_ne(jwt_checker_setcb(NULL, NULL, NULL), 0);
	ck_assert_int_ne(jwt_checker_setcb(checker, NULL, "foo"), 0);
	ck_assert_ptr_null(jwt_checker_getctx(NULL));

	/* Changing ctx for cb */
	ret = jwt_checker_setcb(checker, __verify_wcb, NULL);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_null(jwt_checker_getctx(checker));
	ret = jwt_checker_setcb(checker, NULL, "foo");
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt_checker_getctx(checker));
	ret = jwt_checker_setcb(checker, NULL, NULL);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_null(jwt_checker_getctx(checker));

	/* Some claims stuff */
	ck_assert_ptr_null(jwt_checker_claim_get(NULL, JWT_CLAIM_SUB));
	ck_assert_ptr_null(jwt_checker_claim_get(checker, JWT_CLAIM_IAT));
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

	read_json("oct_key_256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);

	free_key();
}
END_TEST

START_TEST(hs256_no_key)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"JWT has signature, but no key was given");
}
END_TEST

START_TEST(hs256_wrong_key)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("ec_key_secp384r1_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_NONE, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key alg does not match JWT");

	free_key();
}
END_TEST

START_TEST(hs256_token_failed)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("eddsa_key_ed25519_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Token failed verification");

	free_key();
}
END_TEST

START_TEST(hs256_wrong_key_alg)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("eddsa_key_ed25519_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_EDDSA, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Config alg does not match JWT");

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

static int __just_fail_cb(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	(void)config;
	return 1;
}

START_TEST(just_fail_wcb)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj"
		"0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("oct_key_256.json");

	ret = jwt_checker_setcb(checker, __just_fail_cb, "testing");
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

START_TEST(claim_setgetdel)
{
	jwt_checker_auto_t *checker = NULL;
	const char *out = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_ISS, "disk.swissdisk.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_AUD, "public");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_claim_set(checker, JWT_CLAIM_AUD, "employees");
	ck_assert_int_eq(ret, 0);

	out = jwt_checker_claim_get(checker, JWT_CLAIM_AUD);
	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq(out, "employees");

	ret = jwt_checker_claim_del(checker, JWT_CLAIM_AUD);
	ck_assert_int_eq(ret, 0);

	out = jwt_checker_claim_get(checker, JWT_CLAIM_AUD);
	ck_assert_ptr_null(out);
}
END_TEST

START_TEST(claim_time_set)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, 360);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, 480);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, 360);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, 480);
	ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(verify_ps256_nosig)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI"
		"6ZmFsc2UsImlhdCI6MTczNjY5NDU5NCwiaXNzIjoiaHR0cHM6Ly9zd2lzc2Rp"
		"c2suY29tIiwidXNlciI6ImJlbmNvbGxpbnMifQ.";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("rsa_pss_key_2048.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_PS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Expected a signature, but JWT has none");

	free_key();
}
END_TEST

START_TEST(verify_ps256_bad_b64_sig)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI"
		"6ZmFsc2UsImlhdCI6MTczNjY5NDU5NCwiaXNzIjoiaHR0cHM6Ly9zd2lzc2Rp"
		"c2suY29tIiwidXNlciI6ImJlbmNvbGxpbnMifQ.eyJhbGciOiJQUzI1N*IsIn"
		"R5cCI6I!pXVCJ9";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("rsa_pss_key_2048.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_PS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Error decoding signature");

	free_key();
}
END_TEST

START_TEST(verify_ps256_bad_b64_sig_255)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI"
		"6ZmFsc2UsImlhdCI6MTczNjY5NDU5NCwiaXNzIjoiaHR0cHM6Ly9zd2lzc2Rp"
		"c2suY29tIiwidXNlciI6ImJlbmNvbGxpbnMifQ.eyJhbGciOiJQUzI1N[IsIn"
		"R5cCI6I!pXVCJ9";
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("rsa_pss_key_2048.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_PS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			 "Error decoding signature");

	free_key();
}
END_TEST

START_TEST(verify_ps256_bad_sig)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI"
		"6ZmFsc2UsImlhdCI6MTczNjY5NDU5NCwiaXNzIjoiaHR0cHM6Ly9zd2lzc2Rp"
		"c2suY29tIiwidXNlciI6ImJlbmNvbGxpbnMifQ.eyJhbGciOiJQUzI1NiIsIn"
		"R5cCI6IkpXVCJ9";
	const char *err;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("rsa_pss_key_2048.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_PS256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);

	err = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(err);
	ck_assert_ptr_nonnull(strstr(err, "Failed to verify signature"));

	free_key();
}
END_TEST

START_TEST(verify_es256_bad_sig)
{
	jwt_checker_auto_t *checker = NULL;
	const char token[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI"
		"xMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlh"
		"dCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqU"
		"SLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
	const char *err;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json("eddsa_key_ed25519_pub_fake_es256.json");

	ret = jwt_checker_setkey(checker, JWT_ALG_ES256, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);

	err = jwt_checker_error_msg(checker);
	ck_assert_ptr_nonnull(err);
	/* Fails in different ways depending on the backend */
	ck_assert_mem_eq(err, "JWT[", 4);

	free_key();
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
	tcase_add_loop_test(tc_core, verify_bad_header, 0, i);
	tcase_add_loop_test(tc_core, verify_bad_payload, 0, i);
	tcase_add_loop_test(tc_core, verify_rsapss384, 0, i);
	tcase_add_loop_test(tc_core, verify_wcb, 0, i);
	tcase_add_loop_test(tc_core, just_fail_wcb, 0, i);
	tcase_add_loop_test(tc_core, verify_stress, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Error Handling");
	tcase_add_loop_test(tc_core, null_handling, 0, i);
	tcase_add_loop_test(tc_core, bad_alg, 0, i);
	tcase_add_loop_test(tc_core, no_alg, 0, i);
	tcase_add_loop_test(tc_core, no_first_dot, 0, i);
	tcase_add_loop_test(tc_core, no_second_dot, 0, i);
	tcase_add_loop_test(tc_core, alg_none_with_sig, 0, i);
	tcase_add_loop_test(tc_core, hs256_no_key, 0, i);
	tcase_add_loop_test(tc_core, hs256_wrong_key, 0, i);
	tcase_add_loop_test(tc_core, hs256_wrong_key_alg, 0, i);
	tcase_add_loop_test(tc_core, hs256_token_failed, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("HS256 Key Verify");
	tcase_add_loop_test(tc_core, verify_hs256, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_wcb, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_stress, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_fail, 0, i);
	tcase_add_loop_test(tc_core, verify_hs256_fail_stress, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Claims");
	tcase_add_loop_test(tc_core, claim_setgetdel, 0, i);
	tcase_add_loop_test(tc_core, claim_time_set, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("Corner cases");
	tcase_add_loop_test(tc_core, verify_ps256_nosig, 0, i);
	tcase_add_loop_test(tc_core, verify_ps256_bad_b64_sig, 0, i);
	tcase_add_loop_test(tc_core, verify_ps256_bad_b64_sig_255, 0, i);
	tcase_add_loop_test(tc_core, verify_ps256_bad_sig, 0, i);
	tcase_add_loop_test(tc_core, verify_es256_bad_sig, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Checker");
}
