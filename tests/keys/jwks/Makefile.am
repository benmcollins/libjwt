# Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if HAVE_OPENSSL
EXTRA_PROGRAMS = pem_to_jwk jwk_to_pem
endif

AM_CFLAGS = $(OPENSSL_CFLAGS) $(JANSSON_CFLAGS) \
	    -I$(top_srcdir)/include -I$(top_builddir)/include \
	    -I$(top_srcdir)/libjwt

AM_LDFLAGS = -L$(top_builddir)/libjwt \
		$(OPENSSL_LDFLAGS) $(JANSSON_LDFLAGS)

AM_CPPFLAGS = $(OPENSSL_INCLUDES)

pem_to_jwk_LDFLAGS = -static $(AM_LDFLAGS)

LDADD = -ljwt $(JANSSON_LIBS) $(OPENSSL_LIBS) 
