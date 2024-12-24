# Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include

lib_LTLIBRARIES = libjwt.la

libjwt_la_SOURCES = jwt.c jwt-verify.c jwt-encode.c jwks.c \
	jwt-crypto-ops.c jwt-memory.c jwt-setget.c ../libjwt/jwt-validate.c \
	base64.c jwt-private.h base64.h ll.h

libjwt_la_LDFLAGS = -version-info $(LIBJWT_VERSION_INFO) $(OPENSSL_LDFLAGS) \
	$(GNUTLS_LDFLAGS) $(MBEDTLS_LIBS) $(JANSSON_LDFLAGS) -no-undefined

libjwt_la_CPPFLAGS = $(OPENSSL_INCLUDES) $(MBEDTLS_INCS) $(GNUTLS_INCLUDES) \
	$(CODE_COVERAGE_CPPFLAGS) $(AM_CPPFLAGS)

libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(GNUTLS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) -D_GNU_SOURCE

libjwt_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(GNUTLS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

if HAVE_OPENSSL
libjwt_la_SOURCES += openssl/jwk-parse.c openssl/sign-verify.c
endif

if HAVE_GNUTLS
libjwt_la_SOURCES += gnutls/jwk-parse.c gnutls/sign-verify.c
endif

if HAVE_MBEDTLS
libjwt_la_SOURCES += mbedtls/jwk-parse.c mbedtls/sign-verify.c
endif

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
