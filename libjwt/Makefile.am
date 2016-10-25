lib_LTLIBRARIES = libjwt.la
libjwt_la_SOURCES = jwt.c
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# XXX Update this in CMakeLists.txt as well
libjwt_la_LDFLAGS = -version-info 2:1:2 $(OPENSSL_LDFLAGS) $(JANSSON_LDFLAGS)
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(COVERAGE_CFLAGS) $(OPENSSL_CFLAGS)
libjwt_la_LIBADD = $(JANSSON_LIBS) $(COVERAGE_LDFLAGS) $(OPENSSL_LIBS)

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
