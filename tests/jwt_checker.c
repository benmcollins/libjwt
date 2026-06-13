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
	jwt_checker_auto_t *checker = NULL;
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
	free_key();

	jwt_checker_error_clear(checker);

	read_json("oct_key_256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_ES256, g_item);
	ck_assert_int_ne(ret, 0);
	free_key();

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
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* Algorithm confusion: an OKP/EdDSA JWK must not be settable for
	 * HS256 (GHSA-q843-6q5f-w55g). setkey rejects up front. */
	read_json("eddsa_key_ed25519_pub.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

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
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* Algorithm confusion: an OKP/EdDSA JWK must not be settable for
	 * an EC algorithm like ES256 (GHSA-q843-6q5f-w55g). setkey rejects
	 * up front before the broken-signature path is ever reached. */
	read_json("eddsa_key_ed25519_pub_fake_es256.json");
	ret = jwt_checker_setkey(checker, JWT_ALG_ES256, g_item);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Key type does not match algorithm");

	free_key();
}
END_TEST

/* @rfc{7515,4.1.11} "crit" header handling on the checker side. */

/* {"alg":"none","crit":["exp1"],"exp1":true} . {} . */
#define CRIT_TOKEN_PRESENT \
	"eyJhbGciOiJub25lIiwiY3JpdCI6WyJleHAxIl0sImV4cDEiOnRydWV9.e30."

START_TEST(crit_unsupported)
{
	const char token[] = CRIT_TOKEN_PRESENT;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* "exp1" is present in the header but not declared understood. */
	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Unsupported critical header: \"exp1\"");
}
END_TEST

START_TEST(crit_not_in_header)
{
	/* {"alg":"none","crit":["exp1"]} . {"iss":"disk.swissdisk.com"} . */
	const char token[] = "eyJhbGciOiJub25lIiwiY3JpdCI6WyJleHAxIl19."
		"eyJpc3MiOiJkaXNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* We understand "exp1", but it's listed without being in the header.
	 * The "present in header" check fires before the "understood" check. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"\"crit\" lists \"exp1\" which is not in the header");
}
END_TEST

START_TEST(crit_understood)
{
	/* {"alg":"none","crit":["exp1"],"exp1":true} . {} . */
	const char token[] =
		"eyJhbGciOiJub25lIiwiY3JpdCI6WyJleHAxIl0sImV4cDEiOnRydWV9.e30.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* Declaring it understood and present in the header -> passes. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);
	/* Duplicate registration is a no-op success. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(crit_empty)
{
	/* {"alg":"none","crit":[]} . {} . */
	const char token[] = "eyJhbGciOiJub25lIiwiY3JpdCI6W119.e30.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"\"crit\" header must not be empty");
}
END_TEST

START_TEST(crit_not_array)
{
	/* {"alg":"none","crit":"exp1"} . {} . */
	const char token[] = "eyJhbGciOiJub25lIiwiY3JpdCI6ImV4cDEifQ.e30.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"\"crit\" header must be an array");
}
END_TEST

START_TEST(crit_non_string_entry)
{
	/* {"alg":"none","crit":[123]} . {} . */
	const char token[] = "eyJhbGciOiJub25lIiwiY3JpdCI6WzEyM119.e30.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"\"crit\" header entries must be strings");
}
END_TEST

START_TEST(crit_absent)
{
	/* No "crit" header is the baseline and must still verify. */
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJka"
		"XNrLnN3aXNzZGlzay5jb20ifQ.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* Declaring understood names is harmless when no "crit" is present. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);
	ret = jwt_checker_understands(checker, "exp2");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(crit_understands_null)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_understands(NULL, "exp1");
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_understands(checker, NULL);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Must pass a header name");

	jwt_checker_error_clear(checker);

	ret = jwt_checker_understands(checker, "");
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Must pass a header name");
}
END_TEST

START_TEST(crit_roundtrip)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	jwt_value_t jval;
	int ret;

	SET_OPS();

	/* Build a token that marks a custom header "exp1" as critical. */
	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);

	ret = jwt_builder_enable_iat(builder, 0);
	ck_assert_int_eq(ret, 1);

	jwt_set_SET_BOOL(&jval, "exp1", 1);
	ret = jwt_builder_header_set(builder, &jval);
	ck_assert_int_eq(ret, 0);

	ret = jwt_builder_setcrit(builder, "exp1");
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	/* A checker that does NOT understand "exp1" must reject it. */
	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Unsupported critical header: \"exp1\"");

	/* Once it declares "exp1" understood, the same token verifies. */
	jwt_checker_error_clear(checker);
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);
}
END_TEST

/* {"alg":"none","crit":["exp1","exp2"],"exp1":true,"exp2":true} . {} . */
#define CRIT_TOKEN_TWO \
	"eyJhbGciOiJub25lIiwiY3JpdCI6WyJleHAxIiwiZXhwMiJdLCJleHAxIjp0cnVlLCJ" \
	"leHAyIjp0cnVlfQ.e30."

START_TEST(crit_second_unsupported)
{
	const char token[] = CRIT_TOKEN_TWO;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* First entry understood, second is not: the loop must advance to
	 * the second entry and reject it. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Unsupported critical header: \"exp2\"");
}
END_TEST

START_TEST(crit_both_understood)
{
	const char token[] = CRIT_TOKEN_TWO;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* Both entries understood and present: full iteration succeeds. */
	ret = jwt_checker_understands(checker, "exp1");
	ck_assert_int_eq(ret, 0);
	ret = jwt_checker_understands(checker, "exp2");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(crit_understood_no_match)
{
	const char token[] = CRIT_TOKEN_PRESENT;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* A populated understood list that does NOT contain the listed crit
	 * name: the inner match loop must run to completion and reject. */
	ret = jwt_checker_understands(checker, "other");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Unsupported critical header: \"exp1\"");
}
END_TEST

/* @rfc{7519,4.1.7} jti verification callback. */

/* {"alg":"none"} . {"jti":"abc-123"} . */
#define JTI_TOKEN "eyJhbGciOiJub25lIn0.eyJqdGkiOiJhYmMtMTIzIn0."

static int __jti_check(const jwt_t *jwt, jwt_config_t *config, const char *jti)
{
	ck_assert_ptr_nonnull(jwt);
	ck_assert_ptr_nonnull(config);
	ck_assert_str_eq(config->ctx, "pool");
	ck_assert_str_eq(jti, "abc-123");

	return 0;
}

START_TEST(jti_verify)
{
	const char token[] = JTI_TOKEN;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setjti(checker, __jti_check, "pool");
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_eq(ret, 0);
}
END_TEST

static int __jti_reject(const jwt_t *jwt, jwt_config_t *config, const char *jti)
{
	(void)jwt;
	(void)config;
	(void)jti;
	return 1;
}

START_TEST(jti_verify_reject)
{
	const char token[] = JTI_TOKEN;
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setjti(checker, __jti_reject, NULL);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
}
END_TEST

START_TEST(jti_verify_missing)
{
	/* {"alg":"none"} . {"iss":"x"} . — no jti, but a jti cb is set. */
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setjti(checker, __jti_reject, NULL);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
}
END_TEST

START_TEST(jti_verify_not_string)
{
	/* {"alg":"none"} . {"jti":123} . — jti present but not a string. */
	const char token[] = "eyJhbGciOiJub25lIn0.eyJqdGkiOjEyM30.";
	jwt_checker_auto_t *checker = NULL;
	int ret;

	SET_OPS();

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	/* The cb must never be reached for a non-string jti. */
	ret = jwt_checker_setjti(checker, __jti_reject, NULL);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
}
END_TEST

START_TEST(jti_setjti_null)
{
	jwt_checker_auto_t *checker = NULL;
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);

	ret = jwt_checker_setjti(NULL, __jti_check, "pool");
	ck_assert_int_ne(ret, 0);

	ret = jwt_checker_setjti(checker, NULL, "pool");
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Setting ctx without a cb won't work");
	jwt_checker_error_clear(checker);

	ret = jwt_checker_setjti(checker, __jti_check, "old");
	ck_assert_int_eq(ret, 0);
	ret = jwt_checker_setjti(checker, NULL, "pool");
	ck_assert_int_eq(ret, 0);
	ret = jwt_checker_setjti(checker, NULL, NULL);
	ck_assert_int_eq(ret, 0);
}
END_TEST

/* End-to-end: build a token with a generated jti, then verify it twice
 * against a one-shot "pool". The first verify consumes the id; the second
 * is rejected as a replay. */
static char *__jti_pool_gen(const jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	(void)config;
	return strdup("pool-id-1");
}

static int __jti_pool_check(const jwt_t *jwt, jwt_config_t *config,
			    const char *jti)
{
	int *seen = config->ctx;

	(void)jwt;
	ck_assert_str_eq(jti, "pool-id-1");

	if (*seen)
		return 1;	/* already consumed -> replay */

	*seen = 1;
	return 0;
}

START_TEST(jti_pool_roundtrip)
{
	jwt_builder_auto_t *builder = NULL;
	jwt_checker_auto_t *checker = NULL;
	char_auto *out = NULL;
	int seen = 0;
	int ret;

	SET_OPS();

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ret = jwt_builder_setjti(builder, __jti_pool_gen, NULL);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ret = jwt_checker_setjti(checker, __jti_pool_check, &seen);
	ck_assert_int_eq(ret, 0);

	/* First use: accepted and consumed. */
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_eq(ret, 0);

	/* Replay: same id, now rejected. */
	jwt_checker_error_clear(checker);
	ret = jwt_checker_verify(checker, out);
	ck_assert_int_ne(ret, 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker),
			"Failed one or more claims");
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

	tc_core = tcase_create("Crit Header");
	tcase_add_loop_test(tc_core, crit_unsupported, 0, i);
	tcase_add_loop_test(tc_core, crit_not_in_header, 0, i);
	tcase_add_loop_test(tc_core, crit_understood, 0, i);
	tcase_add_loop_test(tc_core, crit_empty, 0, i);
	tcase_add_loop_test(tc_core, crit_not_array, 0, i);
	tcase_add_loop_test(tc_core, crit_non_string_entry, 0, i);
	tcase_add_loop_test(tc_core, crit_absent, 0, i);
	tcase_add_loop_test(tc_core, crit_understands_null, 0, i);
	tcase_add_loop_test(tc_core, crit_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, crit_second_unsupported, 0, i);
	tcase_add_loop_test(tc_core, crit_both_understood, 0, i);
	tcase_add_loop_test(tc_core, crit_understood_no_match, 0, i);
	suite_add_tcase(s, tc_core);

	tc_core = tcase_create("JTI");
	tcase_add_loop_test(tc_core, jti_verify, 0, i);
	tcase_add_loop_test(tc_core, jti_verify_reject, 0, i);
	tcase_add_loop_test(tc_core, jti_verify_missing, 0, i);
	tcase_add_loop_test(tc_core, jti_verify_not_string, 0, i);
	tcase_add_loop_test(tc_core, jti_setjti_null, 0, i);
	tcase_add_loop_test(tc_core, jti_pool_roundtrip, 0, i);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT Checker");
}
