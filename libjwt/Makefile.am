lib_LTLIBRARIES = libjwt.la

libjwt_la_SOURCES = jwt.c base64.c

if HAVE_OPENSSL
libjwt_la_SOURCES += jwt-openssl.c
else
libjwt_la_SOURCES += jwt-gnutls.c
endif

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libjwt_la_LDFLAGS = -version-info 7:0:7 $(OPENSSL_LDFLAGS) $(GNUTLS_LDFLAGS) $(JANSSON_LDFLAGS) -no-undefined
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) $(GNUTLS_INCLUDES) $(CODE_COVERAGE_CPPFLAGS) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(GNUTLS_CFLAGS) $(CODE_COVERAGE_CFLAGS) -D_GNU_SOURCE
libjwt_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(GNUTLS_LIBS) $(CODE_COVERAGE_LDFLAGS)

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
