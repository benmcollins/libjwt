/* Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_TESTS_H
#define JWT_TESTS_H

#include "config.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

static const char *jwt_test_ops[] = {
#ifdef HAVE_OPENSSL
	"openssl",
#endif
#ifdef HAVE_GNUTLS
	"gnutls",
#endif
	NULL
};

#define JWT_TEST_MAIN(__title) ({					\
	int number_failed = 0;						\
	SRunner *sr;							\
	Suite *s;							\
									\
	s = libjwt_suite(__title);					\
	sr = srunner_create(s);						\
									\
	srunner_run_all(sr, CK_VERBOSE);				\
	number_failed += srunner_ntests_failed(sr);			\
	srunner_free(sr);						\
									\
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;	\
})

#define SET_OPS() ({							\
	ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[_i]), 0);	\
	const char *ops = jwt_get_crypto_ops();				\
	ck_assert_str_eq(ops, jwt_test_ops[_i]);			\
})

#endif /* JWT_TESTS_H */
