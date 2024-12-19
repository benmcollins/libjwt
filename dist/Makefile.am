clean-local:
	rm -rf $(builddir)/rpmbuild

$(top_builddir)/$(PACKAGE)-$(VERSION).tar.bz2:
	$(MAKE) -C $(top_builddir) dist-bzip2

$(builddir)/rpmbuild/SOURCES/$(PACKAGE)-$(VERSION).tar.bz2: $(top_builddir)/$(PACKAGE)-$(VERSION).tar.bz2
	$(MKDIR_P) $(builddir)/rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD}
	$(INSTALL) $< $@

rpm: libjwt.spec $(builddir)/rpmbuild/SOURCES/$(PACKAGE)-$(VERSION).tar.bz2
	rpmbuild @RPMBUILD_OPTS@ -ba --define "_topdir $(builddir)/rpmbuild" libjwt.spec
