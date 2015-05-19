TESTS =			\
	jwt_new		\
	jwt_grant

check_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(CHECK_CFLAGS)
AM_LDFLAGS = -L$(top_srcdir)/libjwt
LDADD = -ljwt $(CHECK_LIBS)
