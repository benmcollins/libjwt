# Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

ACLOCAL_AMFLAGS = -I m4 -I m4-local

# The basics
EXTRA_DIST = LICENSE README.md

# CMake stuff
EXTRA_DIST += CMakeLists.txt		\
	cmake/AutoToolsVersion.cmake	\
	cmake/CodeCoverage.cmake

# Logos and banners
EXTRA_DIST +=				\
	images/LibJWT-800x152.png	\
	images/LibJWT.svg		\
	images/favicon.ico

# Doxygen components
EXTRA_DIST +=							\
	doxygen-extra/doxygen-awesome-fragment-copy-button.js	\
	doxygen-extra/doxygen-awesome.css			\
	doxygen-extra/doxygen-awesome-interactive-toc.js	\
	doxygen-extra/footer.html				\
	doxygen-extra/doxygen-awesome-paragraph-link.js		\
	doxygen-extra/header.html				\
	doxygen-extra/doxygen-awesome-tabs.js			\
	doxygen-extra/libjwt.css

SUBDIRS = include libjwt tests dist
if BUILD_EXAMPLES
SUBDIRS += examples
endif

include $(top_srcdir)/Doxygen.mk

check-valgrind check-code-coverage: all
	$(MAKE) $(AM_MAKEFLAGS) -C tests $@
