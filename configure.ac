dnl This sets it for Autconf and CMake
m4_define([major_version], [2])
m4_define([minor_version], [1])
m4_define([micro_version], [0])
m4_define([libjwt_version], [major_version.minor_version.micro_version])

dnl SONAME History
dnl v1.12.1      0 => 1
dnl v1.15.0      1 => 2
dnl http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
m4_define([so_current],		[13])
m4_define([so_revision],	[1])
m4_define([so_age],		[11])
m4_define([libjwt_version_info], [so_current:so_revision:so_age])

m4_define([libjwt_project], [LibJWT])

AC_PREREQ([2.61])
AC_INIT([libjwt_project],[libjwt_version],[https://github.com/benmcollins/libjwt/issues])
AC_LANG([C])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_PREREQ([2.2])
LT_INIT([])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([libjwt/config.h])

AC_SUBST([libjwt_version_info], [libjwt_version_info])

AC_SUBST([AM_CFLAGS], [-Wall])

AC_ARG_WITH([gnutls],
	[AS_HELP_STRING([--with-gnutls],
		[Support GnuTLS for crypto operations @<:@default=check@:>@])],
	[RPMB_GNUTLS="--without gnutls"],
	[with_gnutls=check] [RPMB_GNUTLS="--without gnutls"])

AC_ARG_WITH([openssl],
	[AS_HELP_STRING([--with-openssl],
		[Support OpenSSL for crypto operations @<:@default=check@:>@])],
	[RPMB_OPENSSL="--without openssl"],
	[with_openssl=check] [RPMB_OPENSSL="--without openssl"])

AC_ARG_WITH([mbedtls],
        [AS_HELP_STRING([--with-mbedtls],
                [Support MBedTLS for crypto operations @<:@default=no@:>@])],
        [],
        [with_mbedtls=no])

AS_IF([test "x$with_gnutls" != xno],
	[PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.6.0],
	[AM_CONDITIONAL([HAVE_GNUTLS], [true])]
	[AC_DEFINE([HAVE_GNUTLS], [1], [GnuTLS Support])]
	[HAVE_CRYPTO=true] [RPMB_GNUTLS="--with gnutls"],
	AS_IF([test "x$with_gnutls" != xcheck],
		AC_MSG_FAILURE([--with-gnutls was given but GnuTLS not found])
	))], [AM_CONDITIONAL([HAVE_GNUTLS], [false])])

AS_IF([test "x$with_openssl" != xno],
	[PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0],
        [AM_CONDITIONAL([HAVE_OPENSSL], [true])]
	[AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL Support])]
	[HAVE_CRYPTO=true] [RPMB_OPENSSL="--with openssl"],
        AS_IF([test "x$with_openssl" != xcheck],
		AC_MSG_FAILURE([--with-openssl was given but OpenSSL not found])
	))], [AM_CONDITIONAL([HAVE_OPENSSL], [false])])

CHECK_MBEDTLS

AS_IF([test -z "$HAVE_CRYPTO"],
	[AC_MSG_ERROR([No crypto library detected], [1])], [])

AC_ARG_WITH([examples],
	AS_HELP_STRING([--with-examples], [Build example programs @<:@default=no@:>@]),
	[AM_CONDITIONAL([BUILD_EXAMPLES],[true])],
	[AM_CONDITIONAL([BUILD_EXAMPLES],[false])])

AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$with_examples" != "xno"])

PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4],
	[RPMB_CHECK="--with check"],[RPMB_CHECK="--without check"])

AC_SUBST([RPMBUILD_OPTS],["$RPMB_OPENSSL $RPMB_GNUTLS $RPMB_CHECK"])

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
