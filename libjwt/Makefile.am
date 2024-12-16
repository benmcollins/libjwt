EXTRA_DIST = jwt-private.h CMakeLists.txt cencode.h cdecode.h ccommon.h

lib_LTLIBRARIES = libjwt.la

libjwt_la_SOURCES = jwt.c jwks.c base64.c

# SONAME History
# v1.12.1      0 => 1
# v1.15.0      1 => 2
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

libjwt_la_LDFLAGS = -version-info 13:1:11 $(OPENSSL_LDFLAGS) $(GNUTLS_LDFLAGS) \
	$(MBEDTLS_LIBS) $(JANSSON_LDFLAGS) -no-undefined
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) \
	$(MBEDTLS_INCS) $(GNUTLS_INCLUDES) $(CODE_COVERAGE_CPPFLAGS) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(GNUTLS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) -D_GNU_SOURCE
libjwt_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(GNUTLS_LIBS) $(CODE_COVERAGE_LDFLAGS)

if HAVE_OPENSSL
libjwt_la_SOURCES += jwt-openssl.c jwks-openssl.c
endif

if HAVE_GNUTLS
libjwt_la_SOURCES += jwt-gnutls.c jwks-gnutls.c
endif

if HAVE_MBEDTLS
libjwt_la_SOURCES += jwt-mbedtls.c jwks-mbedtls.c
endif

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
