AC_PREREQ([2.61])
AC_INIT([libjwt],[2.1.0],[https://github.com/benmcollins/libjwt/issues])
AC_LANG([C])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_PREREQ([2.2])
LT_INIT([])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([libjwt/config.h])

AC_SUBST([AM_CFLAGS], [-Wall])

AC_ARG_WITH([gnutls],
	[AS_HELP_STRING([--with-gnutls],
		[Support GnuTLS for crypto operations @<:@default=check@:>@])],
	[],
	[with_gnutls=check])

AC_ARG_WITH([openssl],
	[AS_HELP_STRING([--with-openssl],
		[Support OpenSSL for crypto operations @<:@default=check@:>@])],
	[],
	[with_openssl=check])


AS_IF([test "x$with_gnutls" != xno],
	[PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.6.0],
	[AM_CONDITIONAL([HAVE_GNUTLS], [true])]
	[AC_DEFINE([HAVE_GNUTLS], [1], [GnuTLS Support])]
	[HAVE_CRYPTO=true],
	AS_IF([test "x$with_gnutls" != xcheck],
		AC_MSG_FAILURE([--with-gnutls was given but GnuTLS not found])
	))], [AM_CONDITIONAL([HAVE_GNUTLS], [false])])

AS_IF([test "x$with_openssl" != xno],
	[PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.8],
        [AM_CONDITIONAL([HAVE_OPENSSL], [true])]
	[AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL Support])]
	[HAVE_CRYPTO=true],
        AS_IF([test "x$with_openssl" != xcheck],
		AC_MSG_FAILURE([--with-openssl was given but OpenSSL not found])
	))], [AM_CONDITIONAL([HAVE_OPENSSL], [false])])

AS_IF([test -z "$HAVE_CRYPTO"],
	[AC_MSG_ERROR([no crypto library detected], [1])], [])

AC_ARG_WITH([examples],
	AS_HELP_STRING([--without-examples], [do not build example programs]),
	[],
	[with_examples=yes])

AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$with_examples" != "xno"])

PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [true], [true])

dnl Valgrind defaults
AX_VALGRIND_DFLT([memcheck], [on])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

AX_CODE_COVERAGE

DX_MAN_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN($PACKAGE_NAME, doxygen.cfg)

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	libjwt/Makefile
	examples/Makefile
	tests/Makefile
	libjwt/libjwt.pc
	dist/Makefile
	dist/libjwt.spec
	tests/keys/jwks/Makefile
])

AC_OUTPUT
