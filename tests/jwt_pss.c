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

/* RSA-PSS signature is available with GnuTLS >= 3.6 */
static unsigned char key[16384];
static size_t key_len;

static unsigned char pubkey[16384];
static size_t pubkey_len;

static const char jwt_ps256_invalid[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWF"
	"hYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.IAmCornholio";

static const char jwt_ps256_2048[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.ey"
        "JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYL"
        "VlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.H2fCa4tIgcr3Dcl0oj-zJNp"
        "l8rR8L0tK0UCdsFytjN_VytAgjbqvXORlMlzInx1r0l1aOC5yFGxnYyEu9XpRwh7IRmAXMH"
        "xQyh_8vOcuMJq11qf36vWZLfWe7ILFSTBL_FQbFvNjrRUqOndJPzjeA4kahd4NzYwssfxJi"
        "G_SM4ZZVowaO3JvYGMlbJMrBY4D2sFpovCJ90A1da2dWCuWTXOSX3rXwKWcGDAAjM4iu44k"
        "rAE_hj-RuwIVWUWUCtgg-s-cBFFXmlguo-UBX0UZiR2QY2j4OvKIZFBBysgVSSQ99hGh5Ss"
        "U_CMbn1rQKPyGuNrMobSR6mUklpa-RRK2bw";

static const char jwt_ps384_4096[] = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJpY"
        "XQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYLVlZ"
        "WVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.MCJJY9oeGoIf3s5N-us2Alj1S3"
        "r4R77U8Z_sEtj9IAN7eZxsIUT_CkkFxleUeBOWPkRlCL8QUDmZwAwLk3tjlgauhV1pyhlRl"
        "e2YgS_T2NrNeo6QLLkv_zEQgXnI9UFE0CZjPqBJrfYiLnWU3CqlZ0DE0UGDXUhcXZ_5HFZo"
        "TloIu6I1oa6o5hBBVNiTplWlx0RjnJxr8eBlnFpVuDw1M17ipy8dQ-yNHnRA6wT1btsHavT"
        "C33IuxkEezAxMAkSY4RlJxqpIhjDSYCo0K_ws35yOdjP0uJfyovWUOFfF-I4mfAO9o4aB4o"
        "KSpjiSgBM7l1d5X3gptKgyFm74kg12CsuTeSSaHTTdFRc3W9kIZlt6LOsvc_1ChC5CwXXvz"
        "dbaTsHcubtqRn3p-peDBTZzyMMdRIqQTem_DmozjJadfOQTOVVWZpB8nVmf2KYuVM_HrPiy"
        "BjGxEGFOYqkPVmsYxSA8rFfeKmDpcMD0VTKx9HXFaVKq6r3Q4YvhW0oZrLcjkfMfz2Wjp2W"
        "X7aweh1EmTkKRJLCkY6-OJR1o6_bA9yhQzl9Psv0Hx-Fmr5tJzmckYTMH8s1hM29JJ9Af1v"
        "0-YZgvkYv69b-VTf9kjzhciOiPVCV3qBSOrPBr-DxjG4-53efTBTC9pAtPu8Y9ocwCTULcV"
        "idLvXLUc5UAvTvYTVk";

static const char jwt_ps512_8192[] = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJpY"
        "XQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYLVlZ"
        "WVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.lzFAmXXeOGpnBPx5Luuv96k32X"
        "hb4TEkiO_g1YmzFSU13pBhaXVSH7QyZ8fKtE9vs014pnia-x9r6eG-rjG-YL1hcmtS0fMZg"
        "auRZrxcBFvzxq3RthrgdeAVPXrqwM1cbYDvkijEtT40G93gx07Qyh9peq0KDXk_2ycrSS-w"
        "KQYLk_V7ZgE1qdWYTzcjIoKc6y7Tbs3g4ZZhIaUYO0G0ly5-UIvA_eFjzcJCqsROdpcDdc0"
        "22JTIkkGJEr5NkoooxxbqBIhvA05SG3C2_Td618WZcnI_XVz41aF3stNZaZnJVXFBIhz2F1"
        "mwOL6GORlwcFIKRK8uVdQxujgO-eUJ9NVVn2GkTUJLsHdmahJorWO70v7GZpdRZoM26BDP-"
        "Sj_SSeLhC4VuPG68SUQFgISWW1n4V0HLNj83P1r-Pk9Bio76uOvHNgZe-6gk-IZgQubzj9i"
        "55nkC7VJlvlgpfm1EgqHCq2r_lQ0xmaVYyI7vcTsq514DZQeuXD_0_dD2R15Q0kG-7hBDvZ"
        "UDsQ29usTMnIfH9UpwR3yIA35whS0OCgVB_fDr35eXM2FOESbrTkLE7L39uZY8K6p_Ize1q"
        "F8cQddLShf-lTc3m4dvpohe6w8ZHjWZhf0N_WsyCbxp1clvtlLHPPwX9p_aeKw-wLUuMwZX"
        "D9LAXhiZzAblD4-8WgBPvj0_PVpszrqn-RcEuMvNCym-Rwg9Agx0hZ2TiJ9TGxifess8pbn"
        "8XVwHnZQWnUQ-Nshz10b48eGcLaN28mmcb6DXY-8JIzReJoMBiVMFqr7q-rfUVR5UQ_O0Yj"
        "WBjxdpACMP8LYq2QcsbRGvJwQz3MYit8HDtI2vKA3Xx5HrzdBGfBGlFO7PLb8z0Mhwqbxv4"
        "-ccjkpSU1PyxJCjcr5LWqqUPQV9Y3u4aWfpcegnktbwa2tShUjf_bfVLOZ85jo7ybjuckBY"
        "1D-yu58TYruxmL7CmZznbVqm-fyiFKQkw7ZCpwvgJOHRRGpaIhfy9ScjmBMMupwkBSnqpXk"
        "8tBnOqZ8eKA2Rl9BaJqEA1oqEEH43tNL5jISUgqhsL2jf3AD-ysCiREWVyRX2TDgAhy3vNm"
        "4hM3Ag1mu6Szqi1QFAsHP_xsrd-gFchs6sc4qussikblXjxBac7y4QvOAZh3w4Qfcx2HCe3"
        "TVoLne5oZ_ResHtWkAE6lkPQOjEsiIX5D0yssm3S4x7Kmr27TxmsC4Es9CqZ-vQoTQmkw-o"
        "6CBVvJCTsGZSEltwGM2MNmUNh-YUkZCndd5Q_BjDHw_mamxTkFa6DcNfbJLyil4CyKh2QZE"
        "xJ8yvTQwuGLI9j95C8GPIGIz_bc0aBbIkCHx2YtnI6dzUZZcldVnR29KaINz6Q";

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

static void read_pubkey(const char *pubkey_file)
{
	FILE *fp = fopen(pubkey_file, "r");
	char *pubkey_path;
	int ret = 0;

	ret = asprintf(&pubkey_path, KEYDIR "/%s", pubkey_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(pubkey_path, "r");
	ck_assert_ptr_ne(fp, NULL);

	free(pubkey_path);

	pubkey_len = fread(pubkey, 1, sizeof(pubkey), fp);
	ck_assert_int_ne(pubkey_len, 0);

	ck_assert_int_eq(ferror(fp), 0);

	fclose(fp);

	pubkey[pubkey_len] = '\0';
}

static void __test_alg_key(const char *key_file, const char *pubkey_file, const jwt_alg_t alg)
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

	read_pubkey(pubkey_file);

	ret = jwt_decode(&jwt, out, pubkey, pubkey_len);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ck_assert(jwt_get_alg(jwt) == alg);

	jwt_free(jwt);

	free(out);
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

START_TEST(test_jwt_encode_ps256)
{
	__test_alg_key("rsa_key_2048.pem", "rsa_key_2048-pub.pem", JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_encode_ps384)
{
	__test_alg_key("rsa_key_4096.pem", "rsa_key_4096-pub.pem", JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_encode_ps512)
{
	__test_alg_key("rsa_key_8192.pem", "rsa_key_8192-pub.pem", JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_ps256)
{
	__verify_alg_key("rsa_key_2048-pub.pem", jwt_ps256_2048, JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_verify_ps384)
{
	__verify_alg_key("rsa_key_4096-pub.pem", jwt_ps384_4096, JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_verify_ps512)
{
	__verify_alg_key("rsa_key_8192-pub.pem", jwt_ps512_8192, JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_invalid_token)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_2048.pem");

	ret = jwt_decode(&jwt, jwt_ps256_invalid, key, JWT_ALG_PS512);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_2048.pem");

	ret = jwt_decode(&jwt, jwt_ps256_2048, key, JWT_ALG_PS512);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_8192-pub.pem");

	ret = jwt_decode(&jwt, jwt_ps256_2048, key, JWT_ALG_PS256);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert_file)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_invalid-pub.pem");

	ret = jwt_decode(&jwt, jwt_ps256_2048, key, JWT_ALG_PS256);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_encode_invalid_key)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out = NULL;

	ALLOC_JWT(&jwt);

	read_key("rsa_key_invalid.pem");

	ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_PS512, key, key_len);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_eq(out, NULL);

	jwt_free(jwt);
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT RSA Sign/Verify");

	tc_core = tcase_create("jwt_rsa");

	tcase_add_test(tc_core, test_jwt_encode_ps256);
	tcase_add_test(tc_core, test_jwt_encode_ps384);
	tcase_add_test(tc_core, test_jwt_encode_ps512);
	tcase_add_test(tc_core, test_jwt_verify_ps256);
	tcase_add_test(tc_core, test_jwt_verify_ps384);
	tcase_add_test(tc_core, test_jwt_verify_ps512);
	tcase_add_test(tc_core, test_jwt_verify_invalid_token);
	tcase_add_test(tc_core, test_jwt_verify_invalid_alg);
	tcase_add_test(tc_core, test_jwt_verify_invalid_cert);
	tcase_add_test(tc_core, test_jwt_verify_invalid_cert_file);
	tcase_add_test(tc_core, test_jwt_encode_invalid_key);

	tcase_set_timeout(tc_core, 120);

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
