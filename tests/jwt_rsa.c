/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>

#include <jwt.h>

/* Constant time to make tests consistent. */
#define TS_CONST	1475980545L

/* Macro to allocate a new JWT with checks. */
#define ALLOC_JWT(__jwt) do {		\
	int __ret = jwt_new(__jwt);	\
	ck_assert_int_eq(__ret, 0);	\
	ck_assert_ptr_ne(__jwt, NULL);	\
} while(0)

/* Older check doesn't have this. */
#ifndef ck_assert_ptr_ne
#define ck_assert_ptr_ne(X, Y) ck_assert(X != Y)
#define ck_assert_ptr_eq(X, Y) ck_assert(X == Y)
#endif

#ifndef ck_assert_int_gt
#define ck_assert_int_gt(X, Y) ck_assert(X > Y)
#endif

static unsigned char key[16384];
static size_t key_len;

static const char jwt_rs256_2048[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWF"
	"hYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.QKpsGhSvkF3OQCweg"
	"KzbJsfhzgMrRjFGgBOR3zmBXEJwZiTF0Ns_-TcTweLHTmskeFs0ZA0ezDlRx_LcqLm60"
	"AW2SqZWhhLQX9sN8AzTDugFS-C4P5oPNEq2QPNKDbvUzl8bwM15YracM232MsqNUwkTO"
	"334x3PJiRXotqP1TEiiG7DCd7n_F8ClKxrqEimCUtO5isV4Bg5vMAhbYhzbwQ-5IZIJs"
	"Em047BnqR7eZQILDn53Yy9BE9OWxfHPpqliexB1iqCSww4-llkMbvwes0ObiAaLUQXb4"
	"4zRFxhNN2_i5kfxHIdVDqBXuo8MkpolTCe3Pt3JhM9iwWkvgJkW7Q";

static const char jwt_rs384_4096[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWF"
	"hYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.hid-b6F00dSgNeut4"
	"qEVE27E4Vy-EViR8wbJol9erK15fQdURdDEfVYBAmZ_i72qx4EOpCRP4_XmX0G4Qj2JB"
	"5IR8rh8bJKx33rmw1YgM2l0hRQ0b-kKu-FHV4Ng-LinTk3jRYeVn0YkE5ZFqAPVgp4tp"
	"nLLUwheZiGYLeUIRxlzyvVpOaex-qEjw1wJULU1NdhZ5-CIKC9dka4qwFiLV6dezUM1q"
	"la_j-RrmaNYo068GQn0is4RU9PWP_RPNtU_ZAE5NP_Zfy3RA9snwnLDmA4H7h4cNoI43"
	"pv7VPv3MsiLBp1rjeA79od_rTQq7-CAgQpHh1u7VaF1yPPLLvzzFUT6DkDL4g0ztKx6F"
	"RZNBiZFbsCqrLlYGdO2nqqQzqwtq8Az5B2MvKcUAvuHYIwRNj_ce5TGrzA53JDJaXWNL"
	"MYSNzv2yn8HWaxUWG4YXp_EBHJkEVlcNorsoGYeL9vgUxUu6XuopukS8V_ifaimMyLjL"
	"-V15Ydfr-nfRXgNb8W5MC7eYD3Sl5D-5IXzbaRtOLF1OlVBaJAmO0mFn-yz5cIJHPCdx"
	"w5JRXFtcW6SMkbJduBsaN0fKprpHl1Ov3yFj-w1EzzBmA3R6jJUeTUN-UBvIj5TBnkC4"
	"vODr07Iiro2GD0fUXLKmOPaaF7W_4_Vz47deGrDX6YY57FwlV_fb0g";

static const char jwt_rs512_8192[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWF"
	"hYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.I6knmf13HzEtH_qUt"
	"eKt0GTfrtVLlZ0gwac61tDzPRMviyymz9SjiYiPqnsNdtUsNOesfPCIFfGjG7zDx6ZD-"
	"0PugKaOUjMkRWCdnDqAsO4ixDvO3fWDQOVhlLeSxgbyCayVJZvhTAl1iELc8bia1iv43"
	"_VPwph-81fv3TkLfZByDJ1W_9UFE2qdrSCPy4WU0GOgowCUWdA7SCx3gRLfGp8SAVbhm"
	"Urc4Z5j8tb03gv0WnhMsZOtysJqa9Pv_W_G9aqyu2YIYr3zjaJ5pmbUq4xLhS7flOciS"
	"UGrFYrxb29G1hcEcsvN0OhUJsv1oI61wi_4PrHOlLu4x5TqY6eRifPEHjSlVM80qWMUi"
	"FUYzJ5TDfcV_PIBXyBu6idpldwPPbSUVNW_YJoqXBfph0Wgy5q6EXAnF62pT2gH5TvOy"
	"Ln26rgnLWcYCS1qsg17BPlN9q6zgfiUGMKCJZkDISM_aCGBNsCOcHS38fXYUEjOUZ5F2"
	"ikSLBzMC-ETj23tQGpQPvtyBv4RwlLF5upyGA-mn3ZPhY5H_MfbR3cXTgzwEUgRdkcui"
	"cprJ9LxzIemorq8VvgUFXtfgi54hD5vPWK5BPCy_R1t7qx7R_wEoB35l1BRS-ACBP3uD"
	"-88bAJ8c0n7OLGokHhxoaAcaGPuDUclzzlhfEPwIx5KOQtP41dcqrOkDxp459jl2bFfB"
	"VKHBg7agB8bkqwR5ADnuIv8DGUcIuioDXplnkjUK_46DXiey9TuastqVod2hSmmyuXMN"
	"ds-Ssv9e8RRrMWhx8zavfrj-hJNgrZ15x0fqf9qqmBTGpZ_xpmBJy0N1vvD9TgzBkGIS"
	"3QFd1myTH8z8hqHZYTIRXPvjqDDDRZTiLQyrBOxiP2f3pVMy5SSNkEdaFa4_KCclPJrB"
	"lsQivlfCdOvt94DsZdXa235p_Ny_16QtkcMBietxBkhcnGvANukY2zegitIcgU4RnEsg"
	"OqBRHTyvMvka54VfisK1_WoO8mW2CrBhN2BFgSBsIt8LbhbUukT0WXsYKiLoH3CY743k"
	"pVp_OerBp0wPQME--zoibqjTitLJ2pMldAf6E0JeUf5dveu92nCfb2BUjn3nlBhOmI90"
	"N97YtwVRqdHb7SrkAGJLd8gR7-bBS7ZtCmdC_XboPu7CNSf0GfM1ohoKArpGUF5vwYfN"
	"TVxh7f7nJOXSvtLM4Ghpepy5nZWr1vvuxcaJBmG0_48Lp2MBNaOLuudoSUKsI9W9_NJH"
	"RUeZCFZnALciVvwLm4hrVgMqnLrYFVMDsjb361H0CyxTb_Y_56YkjOB8nWUVMaLi27zL"
	"nJz8gTU0TOFdfVzWoH8_aaMsnoU7FyYgzGaN3UshYG6YUldpNVdbl7nAQ";

static void read_key(const char *key_file)
{
	FILE *fp = fopen(key_file, "r");
	char *key_path;
	int ret = 0;

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(key_path, "r");
	ck_assert_ptr_ne(fp, NULL);

	free(key_path);

	key_len = fread(key, 1, sizeof(key), fp);
	ck_assert_int_ne(key_len, 0);

	ck_assert_int_eq(ferror(fp), 0);

	fclose(fp);

	key[key_len] = '\0';
}

static void __test_alg_key(const char *key_file, const char *jwt_str,
			   const jwt_alg_t alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ALLOC_JWT(&jwt);

	read_key(key_file);

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, alg, key, key_len);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, jwt_str);

	free(out);
	jwt_free(jwt);
}

static void __verify_alg_key(const char *key_file, const char *jwt_str,
			     const jwt_alg_t alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key(key_file);

	ret = jwt_decode(&jwt, jwt_str, key, key_len);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ck_assert(jwt_get_alg(jwt) == alg);

	jwt_free(jwt);
}

START_TEST(test_jwt_encode_rs256)
{
	__test_alg_key("rsa_key_2048.pem", jwt_rs256_2048, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_verify_rs256)
{
	__verify_alg_key("rsa_key_2048-pub.pem", jwt_rs256_2048, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_encode_rs384)
{
	__test_alg_key("rsa_key_4096.pem", jwt_rs384_4096, JWT_ALG_RS384);
}
END_TEST

START_TEST(test_jwt_verify_rs384)
{
	__verify_alg_key("rsa_key_4096-pub.pem", jwt_rs384_4096, JWT_ALG_RS384);
}
END_TEST

START_TEST(test_jwt_encode_rs512)
{
	__test_alg_key("rsa_key_8192.pem", jwt_rs512_8192, JWT_ALG_RS512);
}
END_TEST

START_TEST(test_jwt_verify_rs512)
{
	__verify_alg_key("rsa_key_8192-pub.pem", jwt_rs512_8192, JWT_ALG_RS512);
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
	__verify_alg_key("rsa_key_i37-pub.pem", jwt_rsa_i37, JWT_ALG_RS256);
}
END_TEST

START_TEST(test_jwt_encode_rsa_with_ec)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ALLOC_JWT(&jwt);

	read_key("ec_key_secp384r1.pem");

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_RS384, key, key_len);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);
	ck_assert_int_eq(errno, EINVAL);

	jwt_free(jwt);
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT RSA Sign/Verify");

	tc_core = tcase_create("jwt_rsa");

	tcase_add_test(tc_core, test_jwt_encode_rs256);
	tcase_add_test(tc_core, test_jwt_verify_rs256);
	tcase_add_test(tc_core, test_jwt_encode_rs384);
	tcase_add_test(tc_core, test_jwt_verify_rs384);
	tcase_add_test(tc_core, test_jwt_encode_rs512);
	tcase_add_test(tc_core, test_jwt_verify_rs512);
	tcase_add_test(tc_core, test_jwt_verify_rsa_i37);
	tcase_add_test(tc_core, test_jwt_encode_rsa_with_ec);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
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
