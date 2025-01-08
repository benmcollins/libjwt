/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

static const char jwt_ps256_2048[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.B9gxqtbZae"
	"9PyGkjQaBMyBITOieALP39yCDSqmynmvnE2L8JJzNxOKjm5dy_ORhYjagghE18ti90v2"
	"whAwRFFvA7MlQC2rQm-4pXrHqAyhT7Dl1_lSeL98WGToZgJ646WLjr-SwbMNjp3RWwZz"
	"F-IwnB1D1f-RoA9yUoaNEFHUYVuL4okVj4ImnUE07pW-l2eal3bxUg6lzqGWSctbT46t"
	"y8qFlsOyrifev3y_z6-eKPHUruYEbWb1zw3-snBtcPfGMWAQ91PVoNkPLTO6G56I8FAF"
	"IufXyyp6k9VuKQ_WRzRQhwO8zBOto4RsTUjYbDJEY2FSFYVZUdPctwojNlCw";

static const char jwt_ps384_2048[] = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.GY8aZobXTy"
	"6DzooRUt6vwgBbWwWvTchFtDCVMto_NM68aqT_OI8_X1MAHwE7ppS1S-yxg1aEeGzZEG"
	"VEAdeIzswd7ilCpQrUQ2Qcym6SuK3NAKLtr6NyUZwdaEPTeEx3GWQbmvY66hVs7g2o4c"
	"luSfp3I4McgLCm-HS5Dl_xHoyV_1ympz_n3n7YDoe5l0EoHaX3-XPMtUvL4kxeMV5pLh"
	"72Yj2qNM5Dbbe9F_WSxoeQsyktg8MmPb22LWAAW7uafazr7TinJvPtBhPqT7hc2sUFbA"
	"Jui_TSM60Kjfqg15QQELifywNvgW0ZO6xKEI5GKgaIi2S9F2iqQehBBkjMrg";

static const char jwt_ps512_2048[] = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.OxnjxVNAEC"
	"xEnNVg6S6sx-JIxOq3sJimEefq4OONsYomWz1TAM8_42bmAnvda0bhC8LTmIogQwnYj3"
	"qIYrjef3s7nrs5USS3_ffqeMuog_Xp7cH1YhVwvkXEWzfeT-SLZiEdxGBrPvEASxwzv0"
	"CitQrfDGvFe20UXkhAvOKIc_1K5Fzv9IQiaKaPR2Jg8Ub0qQ6qZq1whnwDbjutWCFlW3"
	"62UOQbhA2WtE72Q60OFXMr2J0PYrScGgTRRrL6V2G7cNRend14FzDFG586dGUCwp9iKF"
	"nCrshFefpaFsOJYHG70Ka6CNIDG4LDiLatjjz1UCtAgbnHfy9qyJEpcJYPWg";

static const char jwt_ps256_2048_invalid[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6Ikp"
	"XVCJ9.eyJpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbS"
	"IsInJlZiI6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.WX"
	"41yYTKxf6lDg7toDAAnwuLKCUSdEWUsJ-5neEbOPE4l09EEIDW2cjK4NZkAgySgCZHCa"
	"NUSn8XaOouoLoEMVua5f0g6U-_-c380KRfmiqFGe39vjHCqiw8j-WkdxHisi7eXw3fvL"
	"kp0VoyeWA6Fnp2x-shfHU5Br67Wagp7OgCk-SvVL08xyfvgZr6fzEqc486zdNhQE71Pv"
	"in5dRQ75Lg3rr1W8Xmx2zRrFKZALsEwGMhRL7e-x46mt6KF1UlwTYAW6FYoKTrrW62sH"
	"OgpgvsIwhE93RfCmJ_xvZNkKrqnB6RxfpHEbZYTS8iAI3va2S8IBEL_pH-2etsr1fqAg";

#define RSA_PSS_KEY_PRE "rsa_pss_key_2048"

#define PS_KEY_PRIV_256 RSA_PSS_KEY_PRE ".json"
#define PS_KEY_PUB_256 RSA_PSS_KEY_PRE "_pub.json"

#define PS_KEY_PRIV_384 RSA_PSS_KEY_PRE "-384.json"
#define PS_KEY_PUB_384 RSA_PSS_KEY_PRE "-384_pub.json"

#define PS_KEY_PRIV_512 RSA_PSS_KEY_PRE "-512.json"
#define PS_KEY_PUB_512 RSA_PSS_KEY_PRE "-512_pub.json"

static void __test_rsa_pss_encode(const char *priv_key_file,
				  const char *pub_key_file,
				  const jwt_alg_t alg)
{
	jwt_auto_t *jwt = NULL;
	jwt_value_t jval;
	int ret;
	char *out;

	CREATE_JWT(jwt, priv_key_file, alg);

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

	free_key();

	__verify_alg_key(pub_key_file, out, alg);

	free(out);
}

START_TEST(test_jwt_encode_ps256)
{
	SET_OPS();
	__test_alg_key(JWT_ALG_PS256, PS_KEY_PRIV_256, PS_KEY_PUB_256);
}
END_TEST

START_TEST(test_jwt_encode_ps384)
{
	SET_OPS();
	__test_rsa_pss_encode(PS_KEY_PRIV_384, PS_KEY_PUB_384, JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_encode_ps512)
{
	SET_OPS();
	__test_rsa_pss_encode(PS_KEY_PRIV_512, PS_KEY_PUB_512, JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_ps256)
{
	SET_OPS();
	__verify_alg_key(PS_KEY_PUB_256, jwt_ps256_2048, JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_verify_ps384)
{
	SET_OPS();
	__verify_alg_key(PS_KEY_PUB_384, jwt_ps384_2048, JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_verify_ps512)
{
	SET_OPS();
	__verify_alg_key(PS_KEY_PUB_512, jwt_ps512_2048, JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_invalid_rsa_pss)
{
	jwt_t *jwt = NULL;

	SET_OPS();

	read_key(PS_KEY_PUB_256);
	t_config.alg = JWT_ALG_PS256;
	jwt = jwt_verify(jwt_ps256_2048_invalid, &t_config);
	free_key();
	ck_assert_ptr_nonnull(jwt);
	ck_assert_int_ne(jwt_error(jwt), 0);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_rsa_pss");

	tcase_add_loop_test(tc_core, test_jwt_encode_ps256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_ps384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_encode_ps512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_ps256, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_ps384, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_ps512, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_verify_invalid_rsa_pss, 0, i);

	tcase_set_timeout(tc_core, 120);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT RSA-PSS Sign/Verify");
}
