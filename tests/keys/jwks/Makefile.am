noinst_PROGRAMS = pem_to_jwk jwk_to_pem

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libjwt
AM_CFLAGS = -Wall -D_GNU_SOURCE
AM_LDFLAGS = -L$(top_builddir)/libjwt
LDADD = -ljwt
