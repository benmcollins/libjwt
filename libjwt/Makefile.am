lib_LTLIBRARIES = libjwt.la
libjwt_la_SOURCES = jwt.c
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libjwt_la_LDFLAGS = -version-info 2:0:2 $(OPENSSL_LDFLAGS)
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(COVERAGE_CFLAGS)
libjwt_la_LIBADD = $(OPENSSL_LIBS) $(JANSSON_LIBS) $(COVERAGE_LDFLAGS)

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
