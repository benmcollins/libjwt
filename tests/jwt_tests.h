/* Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_TESTS_H
#define JWT_TESTS_H

static const char *jwt_test_ops[] = {
	"openssl",
	"gnutls",
	NULL
};

#define JWT_TEST_MAIN(__title) ({						\
	int number_failed = 0;							\
	int i;									\
										\
	for (i = 0; jwt_test_ops[i] != NULL; i++) {				\
		SRunner *sr;							\
		Suite *s;							\
		char *title;							\
		const char *name = jwt_test_ops[i];				\
										\
		if (jwt_set_crypto_ops(name))					\
			continue;						\
										\
		if (asprintf(&title, __title " - %s", jwt_test_ops[i]) < 0)	\
			exit(1);						\
										\
		/* Set this because we fork */					\
		setenv("JWT_CRYPTO", name, 1);					\
										\
		s = libjwt_suite(title);					\
		sr = srunner_create(s);						\
										\
		srunner_run_all(sr, CK_VERBOSE);				\
		number_failed += srunner_ntests_failed(sr);			\
		srunner_free(sr);						\
	}									\
										\
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;		\
})

#endif /* JWT_TESTS_H */
