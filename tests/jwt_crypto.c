/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwt_ops)
{
	int i;

	for (i = 0; jwt_test_ops[i] != NULL; i++) {
		const char *name = jwt_test_ops[i];
		const char *test;

		ck_assert(!jwt_set_crypto_ops(name));

		test = jwt_get_crypto_ops();
		ck_assert_str_eq(test, name);
	}

	/* Assert that this fails */
	ck_assert(jwt_set_crypto_ops("ALWAYS FAIL"));
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create(title);

	tc_core = tcase_create("jwt_crypto");

	tcase_add_test(tc_core, test_jwt_ops);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Crypto Operations");
}
