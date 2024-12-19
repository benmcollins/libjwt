ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = LICENSE README.md CMakeLists.txt 			\
	cmake/AutoToolsVersion.cmake cmake/CodeCoverage.cmake	\
	images/LibJWT-800x152.png images/LibJWT-Icon-95x91.png	\
	images/LibJWT.svg

SUBDIRS = include libjwt tests dist
if BUILD_EXAMPLES
SUBDIRS += examples
endif

include $(top_srcdir)/doxygen.mk

check-valgrind check-code-coverage: all
	$(MAKE) $(AM_MAKEFLAGS) -C tests $@
