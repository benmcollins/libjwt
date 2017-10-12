VERSION=1.8.0

check:
	rpmlint -i dist/c-jwt.spec

rpm-prep:
	mkdir -p ${HOME}/rpmbuild/SOURCES/
	git archive --prefix=c-jwt-${VERSION}/ master | bzip2 > ${HOME}/rpmbuild/SOURCES/c-jwt-${VERSION}.tar.bz2

rpm: rpm-prep
	rpmbuild -ba dist/c-jwt.spec
