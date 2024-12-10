EXTRA_DIST = jwt-private.h CMakeLists.txt cencode.h cdecode.h ccommon.h

lib_LTLIBRARIES = libjwt.la

libjwt_la_SOURCES = jwt.c

# SONAME History
# v1.12.0 => v1.12.1      0 => 1
# v1.14.0 => v1.15.0      1 => 2
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

libjwt_la_LDFLAGS = -version-info 13:0:11 $(OPENSSL_LDFLAGS) $(GNUTLS_LDFLAGS) $(JANSSON_LDFLAGS) -no-undefined
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) $(GNUTLS_INCLUDES) $(CODE_COVERAGE_CPPFLAGS) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(GNUTLS_CFLAGS) $(CODE_COVERAGE_CFLAGS) -D_GNU_SOURCE
libjwt_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(GNUTLS_LIBS) $(CODE_COVERAGE_LDFLAGS)

if HAVE_OPENSSL
libjwt_la_SOURCES += jwt-openssl.c
endif

if HAVE_GNUTLS
libjwt_la_SOURCES += jwt-gnutls.c
endif

if !HAVE_LIBB64
libjwt_la_SOURCES += cdecode.c cencode.c
endif

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
