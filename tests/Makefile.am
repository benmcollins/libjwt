# Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

EXTRA_DIST = jwt_tests.h test-env.sh misc/ruby-eddsa.rb

SUBDIRS = keys

TESTS =			\
	jwt_new		\
	jwt_grant	\
	jwt_header	\
	jwt_dump	\
	jwt_encode	\
	jwt_rsa		\
	jwt_ec		\
	jwt_validate	\
	jwt_rsa_pss	\
	jwt_eddsa	\
	jwt_crypto	\
	jwt_es256k

# JWKS tests are OpenSSL 3 only
if HAVE_OPENSSL
TESTS += jwt_jwks jwt_jwks_errors jwt_jwks_ec jwt_jwks_rsa
endif

check_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(CHECK_CFLAGS) -DKEYDIR="\"$(srcdir)/keys\"" -D_GNU_SOURCE
AM_LDFLAGS = -L$(top_builddir)/libjwt
LDADD = -ljwt $(CHECK_LIBS)

CODE_COVERAGE_EXTRACT_PATTERN = "*/libjwt/*.c"
@CODE_COVERAGE_RULES@
@VALGRIND_CHECK_RULES@

AM_TESTS_ENVIRONMENT =			\
	export TEST="$$f";		\
	. $(srcdir)/test-env.sh;
