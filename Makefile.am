ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include libjwt tests

include $(top_srcdir)/doxygen.mk

check-valgrind: all
	$(MAKE) $(AM_MAKEFLAGS) -C tests check-valgrind

check-code-coverage: all
	$(MAKE) $(AM_MAKEFLAGS) -C tests check-code-coverage
