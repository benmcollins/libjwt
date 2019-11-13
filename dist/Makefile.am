VERSION=@VERSION@

CLEANFILES=libjwt.spec

all:

check:
	rpmlint -i dist/libjwt.spec

rpm-prep:
	cd .. && mkdir -p ./rpmbuild
	cd ../rpmbuild && mkdir -p {SOURCES,SPECS,RPMS,SRPMS,BUILD}
	cd .. && git archive --format=tar --prefix=libjwt-${VERSION}/ master | gzip > ./rpmbuild/SOURCES/v${VERSION}.tar.gz

rpm: rpm-prep
	rpmbuild -ba  --define "_topdir ${PWD}/rpmbuild" libjwt.spec
