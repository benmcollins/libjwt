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
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.HGI3jmvkMT"
	"aot4JM3ElUuEp_ufbG2os116tJdiJsZDM310N3q46vTMAax2QBI3qENEJU_p6qd30i-l"
	"f8imM1-D-PiPjMHxvkN5sOkt35MqEwT8I2Xo3ikn8TSBJKPLM4uBBgO49wG2_0tYTfp0"
	"GPCinBpkSxttH7T3PmK0gqRXde-5TI99XxUbCAtpS9tSAG4RCpQW4XuhA_Hn4WM8pbGZ"
	"vrCvSXWg0ms8fibdDzehuL5AGwJdrabGsPJFU7F2ItrfCaQcVsT6aTSLfFPCv91RK1tl"
	"PlUkpxVg6UdVNwzG44o6UgnCil1jLXbcJmIozsJ_tMQHMg2R6YCslah1MrNA";

static const char jwt_ps512_2048[] = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.ey"
	"JpYXQiOjE0NzU5ODA1NDUsImlzcyI6ImZpbGVzLm1hY2xhcmEtbGxjLmNvbSIsInJlZi"
	"I6IlhYWFgtWVlZWS1aWlpaLUFBQUEtQ0NDQyIsInN1YiI6InVzZXIwIn0.VDihpYTMLt"
	"5mrAphNgo8iJhH5_Ss2uVIDkkARvcNXrUc8RR0dRTeMs-Apw_KsMczwPpE98IR6Z55aV"
	"GWs3-oqv5bp1DWC6-8XaUc3vNfIEV6Rvt2_5D4J8xlOnN-V4Lj99xBOP6A5aeBpRUqWk"
	"ZWpA9cJZOW1oiq-IrSK8VYSfRj6_vdnf-PxHcMziyGX1ITnOqfWtv_-JbaHSXlFyj4hM"
	"gc5pYtS2UC8SEEfHoIk0Pm6zrrcadb5CjQGY7qRi8ESXJhZWsendjwkY8j5Jw_fBs3n1"
	"nXuTVD4G7nBcznQmtdv0trshoYjHRNpAulzoVKgb4k4L4nrm-eM_649rDlOg";

static void read_key(const char *key_file)
{
	FILE *fp = fopen(key_file, "r");
	char *key_path;
	int ret = 0;

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(key_path, "r");
	ck_assert_ptr_ne(fp, NULL);

	jwt_free_str(key_path);

	key_len = fread(key, 1, sizeof(key), fp);
	ck_assert_int_ne(key_len, 0);

	ck_assert_int_eq(ferror(fp), 0);

	fclose(fp);

	key[key_len] = '\0';
}

static void __verify_alg_key(const char *key_file, const char *jwt_str,
			     const jwt_alg_t alg)
{
	jwt_valid_t *jwt_valid = NULL;
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key(key_file);

	ret = jwt_decode(&jwt, jwt_str, key, key_len);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_valid_new(&jwt_valid, alg);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(JWT_VALIDATION_SUCCESS, ret);

	jwt_valid_free(jwt_valid);
	jwt_free(jwt);
}

static void __test_rsa_pss_encode(const char *priv_key_file,
				  const char *pub_key_file,
				  const jwt_alg_t alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ALLOC_JWT(&jwt);

	read_key(priv_key_file);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
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

	__verify_alg_key(pub_key_file, out, alg);

	jwt_free_str(out);
	jwt_free(jwt);
}

START_TEST(test_jwt_encode_ps256)
{
	__test_rsa_pss_encode("rsa-pss_key_2048.pem", "rsa-pss_key_2048-pub.pem", JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_encode_ps384)
{
	__test_rsa_pss_encode("rsa-pss_key_2048.pem", "rsa-pss_key_2048-pub.pem", JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_encode_ps512)
{
	__test_rsa_pss_encode("rsa-pss_key_2048.pem", "rsa-pss_key_2048-pub.pem", JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_ps256)
{
	__verify_alg_key("rsa-pss_key_2048-pub.pem", jwt_ps256_2048, JWT_ALG_PS256);
}
END_TEST

START_TEST(test_jwt_verify_ps384)
{
	__verify_alg_key("rsa-pss_key_2048-pub.pem", jwt_ps384_2048, JWT_ALG_PS384);
}
END_TEST

START_TEST(test_jwt_verify_ps512)
{
	__verify_alg_key("rsa-pss_key_2048-pub.pem", jwt_ps512_2048, JWT_ALG_PS512);
}
END_TEST

START_TEST(test_jwt_verify_invalid_rsa_pss)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key("rsa_key_2048-pub.pem");

	ret = jwt_decode(&jwt, jwt_ps256_2048, key, JWT_ALG_PS256);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_eq(jwt, NULL);
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT RSA-PSS Sign/Verify");

	tc_core = tcase_create("jwt_rsa_pss");

	tcase_add_test(tc_core, test_jwt_encode_ps256);
	tcase_add_test(tc_core, test_jwt_encode_ps384);
	tcase_add_test(tc_core, test_jwt_encode_ps512);
	tcase_add_test(tc_core, test_jwt_verify_ps256);
	tcase_add_test(tc_core, test_jwt_verify_ps384);
	tcase_add_test(tc_core, test_jwt_verify_ps512);
	tcase_add_test(tc_core,test_jwt_verify_invalid_rsa_pss);

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
