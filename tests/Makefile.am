TESTS =			\
	jwt_new		\
	jwt_grant	\
	jwt_dump	\
	jwt_encode	\
	jwt_rsa		\
	jwt_ec

check_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(CHECK_CFLAGS) -DKEYDIR="\"$(srcdir)/keys\""
AM_LDFLAGS = -L$(top_builddir)/libjwt
LDADD = -ljwt $(CHECK_LIBS)
