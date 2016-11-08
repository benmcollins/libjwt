lib_LTLIBRARIES = libjwt.la
libjwt_la_SOURCES = jwt.c
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# XXX Update this in CMakeLists.txt as well
libjwt_la_LDFLAGS = -version-info 3:0:3 $(OPENSSL_LDFLAGS) $(JANSSON_LDFLAGS)
libjwt_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) $(CODE_COVERAGE_CPPFLAGS) -Wall
libjwt_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(CODE_COVERAGE_CFLAGS)
libjwt_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(CODE_COVERAGE_LDFLAGS)

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libjwt.pc
