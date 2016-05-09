/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <check.h>

#include <jwt.h>

extern char *b64uri_decode(char *src, int *result_len);

typedef struct {
	const char *plain_str;
	const char *b64_str;
} test_case_t;

#define claims_txt "{\n" \
  "  \"service1\" : \"On\",\n" \
  "  \"service2\" : \"On\"\n" \
  "}\n"

#define claimsx_txt "{\n" \
  "  \"service1\" : \"On\",\n" \
  "  \"service2\" : \"Off\"\n" \
  "}\n"

#define claimsy_txt "{\n" \
  "  \"service1\" : \"Off\",\n" \
  "  \"service2\" : \"Off\"\n" \
  "}\n"

test_case_t test_list[] = {
	{"0", "MA=="},
	{"00", "MDA="},
	{"000", "MDAw"},
	{"0000", "MDAwMA=="},
	{"00000", "MDAwMDA="},
	{"000000", "MDAwMDAw"},
	{"abc}}>}}?}", "YWJjfX0-fX0_fQ=="},
	{"abc}}>}}?}x", "YWJjfX0-fX0_fXg="},
	{"abc}}>}}?}xy", "YWJjfX0-fX0_fXh5"},
	{claims_txt, "ewogICJzZXJ2aWNlMSIgOiAiT24iLAogICJzZXJ2aWNlMiIgOiAiT24iCn0K"},
	{claimsx_txt, "ewogICJzZXJ2aWNlMSIgOiAiT24iLAogICJzZXJ2aWNlMiIgOiAiT2ZmIgp9Cg=="},
	{claimsy_txt, "ewogICJzZXJ2aWNlMSIgOiAiT2ZmIiwKICAic2VydmljZTIiIDogIk9mZiIKfQo="}
};

#define _NUM_TEST_CASES ( sizeof(test_list) / sizeof(test_case_t) )

START_TEST(test_jwt_base64)
{
  char *result_str;
  int result, result_len;
	const char *test_b64 = test_list[_i].b64_str;
  const char *test_plain = test_list[_i].plain_str;

  result_str = b64uri_decode (test_b64, &result_len);
  printf ("test decoded is %s\n", result_str);
  result = strncmp (result_str, test_plain, result_len);
  free (result_str);
	ck_assert_int_eq(result, 0);
}
END_TEST


Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Decode");

	tc_core = tcase_create("jwt_decode");

	tcase_add_loop_test(tc_core, test_jwt_base64, 0, _NUM_TEST_CASES);

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


