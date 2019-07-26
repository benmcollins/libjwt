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

static unsigned char pubkey[16384];
static size_t pubkey_len;

static const char jwt_rs256_invalid[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWF"
	"hYLVlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.IAmCornholio";

static const char jwt_rs256_2048[] = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.ey"
        "JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLmN5cGhyZS5jb20iLCJyZWYiOiJYWFhYL"
        "VlZWVktWlpaWi1BQUFBLUNDQ0MiLCJzdWIiOiJ1c2VyMCJ9.H2fCa4tIgcr3Dcl0oj-zJNp"
        "l8rR8L0tK0UCdsFytjN_VytAgjbqvXORlMlzInx1r0l1aOC5yFGxnYyEu9XpRwh7IRmAXMH"
        "xQyh_8vOcuMJq11qf36vWZLfWe7ILFSTBL_FQbFvNjrRUqOndJPzjeA4kahd4NzYwssfxJi"
        "G_SM4ZZVowaO3JvYGMlbJMrBY4D2sFpovCJ90A1da2dWCuWTXOSX3rXwKWcGDAAjM4iu44k"
        "rAE_hj-RuwIVWUWUCtgg-s-cBFFXmlguo-UBX0UZiR2QY2j4OvKIZFBBysgVSSQ99hGh5Ss"
        "U_CMbn1rQKPyGuNrMobSR6mUklpa-RRK2bw";

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

START_TEST(test_jwt_encode_ps256)
{
	__test_alg_key("rsa_key_2048.pem", "rsa_key_2048-pub.pem", JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_encode_ps384)
{
	__test_alg_key("rsa_key_2048.pem", "rsa_key_2048-pub.pem", JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_encode_ps512)
{
	__test_alg_key("rsa_key_2048.pem", "rsa_key_2048-pub.pem", JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_invalid_token)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_2048.pem");

	ret = jwt_decode(&jwt, jwt_rs256_invalid, key, JWT_ALG_PS512);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_2048.pem");

	ret = jwt_decode(&jwt, jwt_rs256_2048, key, JWT_ALG_PS512);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_8192-pub.pem");

	ret = jwt_decode(&jwt, jwt_rs256_2048, key, JWT_ALG_PS256);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

START_TEST(test_jwt_verify_invalid_cert_file)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_invalid-pub.pem");

	ret = jwt_decode(&jwt, jwt_rs256_2048, key, JWT_ALG_PS256);
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
