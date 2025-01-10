/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "jwt_tests.h"

START_TEST(test_jwt_ops)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(jwt_test_ops); i++) {
		jwt_test_op_t *op = &jwt_test_ops[i];
		const char *name;
		jwt_crypto_provider_t type;

		ck_assert(!jwt_set_crypto_ops(op->name));

		name = jwt_get_crypto_ops();
		ck_assert_str_eq(name, op->name);

		ck_assert(!jwt_set_crypto_ops_t(op->type));

		type = jwt_get_crypto_ops_t();
		ck_assert_int_eq(type, op->type);
		ck_assert_int_ne(jwt_crypto_ops_supports_jwk(), 0);
	}

	/* Assert that this fails */
	ck_assert(jwt_set_crypto_ops("ALWAYS FAIL"));
	ck_assert(jwt_set_crypto_ops_t((jwt_crypto_provider_t)919192));
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

int main(void)
{
	JWT_TEST_MAIN("LibJWT Crypto Operations");
}
