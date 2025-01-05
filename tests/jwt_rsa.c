/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static const char jwt_rs256_2048[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.RlJPQst_lp"
	"MJUsbnzlT2Mf3xzlHyUlVaQM_PJ1_vpBf1gHkhv-0hm3pa1_HRvpqg5UdDF3iOMLT0GU"
	"j3W8JveaSvXKFeZdRpQGqmC7MZ7NzaYtyaDT7asniIVDf0JomD8Cfq8IdOn2ZREpbuJ6"
	"moPwwvJ2zwL3vY-7w5A7ZQ3fxUedPuzn9n6tbEnuXcbDMyWQjen5poYmmvoIrDbzK0Zb"
	"KbAJ5VrJwME_fZnPHS4c3b8rZGdBJCPI8oT2On6a9LrVqY3riqqHeiSqewfjDsox4tL2"
	"G5KUpqK0oJmnZPGTnNY774PGabpcPBNbfMJqi8o8r0a7pa7sy6B59P7slUdw";

static const char jwt_rs384_4096[] = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.E9e6Chv39H"
	"FQqhfUFcCxUzyS6yHQvBex_OaQNIPqeoPR_FDquiLhQUJj45IGd8_aVT8DvfzTFSHOP1"
	"cP_UbzCYtZ8VC0o-idxyjTnlnqMJy75xNBzPUy6OSpTeX9yVQCtIkT6kIom4j35ABibk"
	"_MdCVqnWG2fijDEeTlLD7uDRcCTGckqQhVOI3t4iIytiUVPnboFiaPLfei_mPcJ6CiOI"
	"QYF4VOWlDllgUFrQ0M0nKm4Pq6bVaBIMzF0hJrPn_7GCV3XmVLthcObljfydaNm_CcIY"
	"g7y_8OT_8yAvDlbKBe5jVeq-7_lLCinarkGUZ5ryA2lbC6yPBgtaAU3g6XxP60n6To7z"
	"akV_5dgcPJFDlTkoBI6pPH3Zf50UYsf-wR4D2J3fP4rcYco4HGtxZ89tfoNYCB8z5-GA"
	"ImSJRbVSsdadwSKKgldlG9XR13Cq-Ox8Hc7qCd1tTC-NeY31XMuWxd9981bQMeGhBkyJ"
	"fFnIksh8xyyO0uOPvgmchOtG8bSImfZZaeBI6TcPJ89Oo3iD6NmPdO5AUqv6NB7Y46zH"
	"GUXCeTuumVk7I_PJ9laICW4-cx1zHDvPY3TphVVTudSqWdUDMjwhrRI23569DByMJE9J"
	"XpTg7HV_17EPTDWExc6TQVkmmY4QbS0pVbKyJTwwKmnu2F9o2fl1N0NOw1SOM";

static const char jwt_rs512_8192[] = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.F3_fF6RGJy"
	"B_apyq_ljxLP7luYC78wT23pPKAyRSMiDi0g-7Yfohv5_p0rBOCsT1H-1_rImWiIcsdJ"
	"87oYfQw95G_pHcK56ag7_a1i-jQCV7ZyRAuesDcM1YRealKvdnof08Jw392h685XNK2l"
	"mqvZ436Hz4oCcQimwuKeR0ndAgm38y-_FswOlb3POwHBJcDtDR3UTvCONyqgcCD5hl5J"
	"edjA8GA0Mvlp4JV2-ctsNYaDOMQRw3S8hJOXvKySQsbckEj8pC_bCrcbSR8BUJBrjM5Q"
	"SLslcYGJopyCYAApGsq3t4-uY3Dx-QjWBMgSIgD9BONjv4VXvsfrllWUQmK88qJ4WQFO"
	"L0PUSJy57lZjpjXReafJcJgdrGI-tFHgqkcb1VxmqnnIFRqadgjJ1BkfFvdExJiOgnvN"
	"SEQ16AYy2FlxZeaabqyOjc8IlGi7Z9hYZgImL_qn0REJXgvxNtabA9-A4cEMWVDtYkCn"
	"F_VyYeMOMYKMuoFW5ubLfOhYhDnd_yvkrLzZ76BGXpHtg7cfpnN8dNWp8irwjSByBH4H"
	"lB0F9NFZydNB8wylFsKesNhmkQYcLnchhA4dBZV888NKVfqIBcM-GWXExtmON0SXg_HX"
	"YmbO6zTgQ4tGAk4HglRWJYlfgORdcBBtnlwUHXm5L7_0J8KHoyNUGbA2XU1krVhBN-A7"
	"sxtLof6MZP8c7p65Oc6DH8FulpmnBt8yVID2GnXPfcLs-RgM8QnlSGbNhn9WT2kmBTIV"
	"eniVfp_IJ40Kd4SROGa_XbXMTufympqyYSSxtqHblGgtolVGdpN05FDvInG0J0dojYxT"
	"_puZ-fvBAMXRPeoC_t_1ScfER4CjsUedbReQLZmE-9nJKhCZKqiba5qCbq8riZYiROGJ"
	"rtVryTywLzw7XX4D-s9oJsEk6ELSRI-buXuCqyCmbdRpFz-i2-VPmNQIalk_0Pq_dOZN"
	"y0GCvcezkhx1quGKPDmFskJnvKZmC70er0DvOQl1A909kFivxIXfTzlu8jUJt8PPi0gU"
	"-nnOGSYxC8tD16vwHvAP3KPYvUzmC2N0r6_yM2_Y-JH5Vypeecbuh66cx18Bqk1nQYfg"
	"BLjuJwQSIKRNNBLtgU7mcyI0Lj4-TWbE-22dYYvKcPMxSmfwAmJUm7ZFUAq_Ok-46AmV"
	"RYg-h7bZZlfutOiWuoBrmnqQ6dEDGjXiEgWhtAx5HG3qn1_vmA3JQxJAWEfuhHa3IWac"
	"MDRrJehImeyDE0H0rpOsxSXOjnDqiFBsf9d0-zJNFvo9tWlK_-d-N40BIy5eZm37FKG7"
	"g2rFmXtuicUs6jiwu0_tHSi1fPKO7YN2ezQc9HAoBvvrur1z_XGbDSmFTQNTv0Cg";

static const char jwt_rs256_invalid[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	".eyJpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJ"
	"YWFhYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.IAmCornholio";

START_TEST(test_jwt_encode_rs256)
{
	SET_OPS();
	__compare_alg_key("rsa_key_2048.pem", jwt_rs256_2048, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_verify_rs256)
{
	SET_OPS();
	__verify_alg_key("rsa_key_2048_pub.pem", jwt_rs256_2048, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_validate_rs256)
{
	jwt_t *jwt = NULL;
	jwt_valid_t *jwt_valid = NULL;
	int ret = 0;

	SET_OPS();

	t_config.alg = JWT_ALG_RS256;

	read_key("rsa_key_2048_pub.pem");
	ret = jwt_verify(&jwt, jwt_rs256_2048, &t_config);
	free_key();
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt);

	jwt_valid_new(&jwt_valid, JWT_ALG_RS256);
	ck_assert_ptr_nonnull(jwt_valid);

	ret = jwt_valid_add_grant(jwt_valid, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_valid_add_grant_int(jwt_valid, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(JWT_VALIDATION_SUCCESS, jwt_validate(jwt, jwt_valid));

	jwt_valid_free(jwt_valid);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_rs384)
{
	SET_OPS();
	__compare_alg_key("rsa_key_4096.pem", jwt_rs384_4096, JWT_ALG_RS384);
}
END_TEST

START_TEST(test_jwt_verify_rs384)
{
	SET_OPS();
	__verify_alg_key("rsa_key_4096_pub.pem", jwt_rs384_4096, JWT_ALG_RS384);
}
END_TEST

START_TEST(test_jwt_encode_rs512)
{
	SET_OPS();
	__compare_alg_key("rsa_key_8192.pem", jwt_rs512_8192, JWT_ALG_RS512);
}
END_TEST

START_TEST(test_jwt_verify_rs512)
{
	SET_OPS();
	__verify_alg_key("rsa_key_8192_pub.pem", jwt_rs512_8192, JWT_ALG_RS512);
}
END_TEST

static const char jwt_rsa_i37[] = "eyJraWQiOiJkWUoxTDVnbWd0eDlWVU9xbVpyd2F6cW"
	"NhK3B5c1lHNUl3N3RSUXB6a3Z3PSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhMDQyZj"
	"Y4My0xODNiLTQ1ZWUtOTZiYy1lNDdlYjhiMzc2MTYiLCJ0b2tlbl91c2UiOiJhY2Nlc3"
	"MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiaXNzIjoiaH"
	"R0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYX"
	"N0LTFfUWJvMXlMZ0ZIIiwiZXhwIjoxNDg1ODgyNDg5LCJpYXQiOjE0ODU4Nzg4ODksIm"
	"p0aSI6Ijg1MTBlMGVkLWU3N2UtNDJmZS1hMmI2LTgyMjAzMDcxZWQyOCIsImNsaWVudF"
	"9pZCI6IjdicTVhanV0czM1anVmamVnMGYwcmhzNnRpIiwidXNlcm5hbWUiOiJhZG1pbj"
	"MifQ.IZqzZEuwKCVT0acHk3p5DnzPSNxg1tLISt8wZCMAHJAnLSdtbtVibrCTZkTLP5z"
	"PD16MgzgsID_CFF2wZXPGBihhyihu1B5W8GimY4eQOKrt4qiLJgK-D8tG6MSZ2K_9DC3"
	"RwhMjrNL4lpu2YoSOgugRdKpJWy4zadtHKptFkKrkI8qjnDoDSkF0kt4I6S1xOcEPuVh"
	"EOrGsfKr5Bm1N3wX9OVQhcTiVugKrpU8x0Mv1AJYdaxKASOQ6fFlNquwfohgLDwy3By3"
	"xU6RoY6ZWhKm5dcGW7H9gqmr9X4aBmHDmYG5KQtodwf0LOYtprPAXCs9X7Ja-7ddJvko"
	"8mDObTA";

START_TEST(test_jwt_verify_rsa_i37)
{
	SET_OPS();
	__verify_alg_key("rsa_key_i37_pub.pem", jwt_rsa_i37, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_encode_rsa_with_ec)
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

	read_key("ec_key_secp384r1.pem");
	ret = jwt_set_alg(jwt, JWT_ALG_RS384, t_config.key, t_config.key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);
	ck_assert_int_eq(errno, EINVAL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_encode_rsa_1024)
{
	JWT_CONFIG_DECLARE(config);
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	jwt_t *jwt = NULL;
	char *out;
	int ret = 0;

	SET_OPS_JWK();

	read_key("rsa_key_1024.json");
	jwk_set = jwks_create(t_config.key);
	free_key();

	ck_assert_ptr_nonnull(jwk_set);
	ck_assert(!jwks_error(jwk_set));

	item = jwks_item_get(jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert(!item->error);

	config.jw_key = item;
	jwt = jwt_create(&config);
	ck_assert_ptr_nonnull(jwt);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	/* Should fail from too few bits in key */
	out = jwt_encode_str(jwt);
	ck_assert_ptr_null(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_verify_invalid_token)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	read_key("rsa_key_2048.pem");
	ret = jwt_verify(&jwt, jwt_rs256_invalid, &t_config);
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

	read_key("rsa_key_2048.pem");
	ret = jwt_verify(&jwt, jwt_rs256_2048, &t_config);
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

	read_key("rsa_key_8192_pub.pem");
	ret = jwt_verify(&jwt, jwt_rs256_2048, &t_config);
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

	read_key("rsa_key_invalid_pub.pem");
	ret = jwt_verify(&jwt, jwt_rs256_2048, &t_config);
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

	read_key("rsa_key_invalid.pem");
	ret = jwt_set_alg(jwt, JWT_ALG_RS512, t_config.key, t_config.key_len);
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

	tc_core = tcase_create("jwt_rsa");

	tcase_add_loop_test(tc_core, test_jwt_encode_rs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_rs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_validate_rs256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_rs384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_rs384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_rs512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_rs512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_rsa_i37, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_rsa_with_ec, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_token, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_alg, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_cert, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_cert_file, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_invalid_key, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_rsa_1024, 0, i);

	tcase_set_timeout(tc_core, 120);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT RSA Sign/Verify");
}
