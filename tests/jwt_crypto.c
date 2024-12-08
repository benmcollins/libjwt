/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>

#include <jwt.h>

#include "jwt_tests.h"

START_TEST(test_jwt_ops)
{
	int i;

	for (i = 0; jwt_test_ops[i] != NULL; i++) {
		const char *name = jwt_test_ops[i];
		const char *test;

		/* Would be nice if we could know what we were compiled with */
                if (jwt_set_crypto_ops(name))
                        continue;

		test = jwt_get_crypto_ops();
		ck_assert_str_eq(test, name);
	}

	/* Assert that this fails */
	ck_assert(jwt_set_crypto_ops("ALWAYS FAIL"));
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Crypto Ops");

	tc_core = tcase_create("jwt_crypto");

	tcase_add_test(tc_core, test_jwt_ops);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = libjwt_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed += srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
