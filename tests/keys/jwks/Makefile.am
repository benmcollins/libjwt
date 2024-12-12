noinst_PROGRAMS = pem_to_jwk jwk_to_pem

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libjwt $(OPENSSL_INCLUDES)
AM_CFLAGS = -Wall -D_GNU_SOURCE $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) -g
AM_LDFLAGS = -L$(top_builddir)/libjwt $(OPENSSL_LDFLAGS) $(JANSSON_LDFLAGS)
LDADD = -ljwt $(JANSSON_LIBS) $(OPENSSL_LIBS)
