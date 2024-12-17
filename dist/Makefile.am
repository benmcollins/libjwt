VERSION=@VERSION@

CLEANFILES=libjwt.spec

rpmcheck:
	rpmlint -i libjwt.spec

rpm-prep: rpmbuild/SOURCES/libjwt-${VERSION}.tar.bz2

rpmbuild/SOURCES/libjwt-${VERSION}.tar.bz2:
	mkdir -p rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD}
	(cd ${abs_top_srcdir} && git archive --format=tar --prefix=libjwt-${VERSION}/ master) | bzip2 > $@

rpm: rpm-prep
	rpmbuild @RPMBUILD_OPTS@ -ba --define "_topdir $(PWD)/rpmbuild" libjwt.spec
