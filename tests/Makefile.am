EXTRA_DIST = CMakeLists.txt keys

TESTS =			\
	jwt_new		\
	jwt_grant	\
	jwt_header	\
	jwt_dump	\
	jwt_encode	\
	jwt_rsa		\
	jwt_ec		\
	jwt_validate	\
	jwt_rsa_pss	\
	jwt_eddsa	\
	jwt_crypto

check_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(CHECK_CFLAGS) -DKEYDIR="\"$(srcdir)/keys\"" -D_GNU_SOURCE
AM_LDFLAGS = -L$(top_builddir)/libjwt
LDADD = -ljwt $(CHECK_LIBS)

nodist_include_HEADERS = jwt_tests.h

@CODE_COVERAGE_RULES@
@VALGRIND_CHECK_RULES@
