# Copyright (C) 2015-2024 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

clean-local:
	rm -rf $(builddir)/rpmbuild

$(top_builddir)/$(PACKAGE)-$(VERSION).tar.bz2:
	$(MAKE) -C $(top_builddir) dist-bzip2

$(builddir)/rpmbuild/SOURCES/$(PACKAGE)-$(VERSION).tar.bz2: $(top_builddir)/$(PACKAGE)-$(VERSION).tar.bz2
	$(MKDIR_P) $(builddir)/rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD}
	$(INSTALL) $< $@

rpm: libjwt.spec $(builddir)/rpmbuild/SOURCES/$(PACKAGE)-$(VERSION).tar.bz2
	rpmbuild @RPMBUILD_OPTS@ -ba --define "_topdir $(builddir)/rpmbuild" libjwt.spec
