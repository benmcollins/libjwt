dnl The use of m4_define here is to make it easy to parse by CMakeLists.txt.
dnl That way there's one source for this info

AC_PREREQ([2.61])

dnl The library version
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

m4_define([libjwt_project],	[LibJWT])
m4_define([libjwt_bugs],	[https://github.com/benmcollins/libjwt/issues])
m4_define([libjwt_url],		[https://libjwt.io])
m4_define([libjwt_brief],	[The C JSON Web Token Library +JWK +JWKS])

AC_INIT([libjwt_project],
	[libjwt_version],
	[libjwt_bugs],
	[],
	[libjwt_url])

AC_SUBST([LIBJWT_VERSION_INFO], [libjwt_version_info])
AC_DEFINE([PACKAGE_DESCRIPTION], ["libjwt_brief"], [Description of this project])
AC_SUBST([PACKAGE_DESCRIPTION], ["libjwt_brief"])

AC_LANG([C])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-bzip2])
LT_PREREQ([2.2])
LT_INIT([])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([libjwt/config.h])

AC_SUBST([AM_CFLAGS], [-Wall])

[RPMB_GNUTLS="--without gnutls"]
[RPMB_OPENSSL="--without openssl"]

AC_ARG_WITH([gnutls],
	[AS_HELP_STRING([--with-gnutls],
		[Support GnuTLS for crypto operations @<:@default=check@:>@])],
	[], [with_gnutls=check])

AC_ARG_WITH([openssl],
	[AS_HELP_STRING([--with-openssl],
		[Support OpenSSL for crypto operations @<:@default=check@:>@])],
	[], [with_openssl=check])

AC_ARG_WITH([mbedtls],
        [AS_HELP_STRING([--with-mbedtls],
                [Support MBedTLS for crypto operations @<:@default=no@:>@])],
        [], [with_mbedtls=no])

AS_IF([test "x$with_openssl" != xno],
	[PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0],
		[have_openssl=yes],
		[AS_IF([test "x$with_openssl" != xcheck],
			AC_MSG_FAILURE([--with-openssl was given but OpenSSL not found])
		)])])

AS_IF([test "x$with_gnutls" != xno],
	[PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.6.0],
		[have_gnutls=yes],
		[AS_IF([test "x$with_gnutls" != xcheck],
			AC_MSG_FAILURE([--with-gnutls was given but GnuTLS not found])
		)])])

AS_IF([test "x$have_gnutls" = xyes],
	dnl We got it
	[AC_DEFINE([HAVE_GNUTLS], [1], [GnuTLS Support])]
	[AM_CONDITIONAL([HAVE_GNUTLS], [true])]
	[have_crypto=yes]
	[RPMB_GNUTLS="--with gnutls"],

	dnl We don't
	[AM_CONDITIONAL([HAVE_GNUTLS], [false])]
)

AS_IF([test "x$have_openssl" = xyes],
	dnl We got it
	[AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL Support])]
	[AM_CONDITIONAL([HAVE_OPENSSL], [true])]
	[have_crypto=yes]
	[RPMB_OPENSSL="--with openssl"],

	dnl We don't
	[AM_CONDITIONAL([HAVE_OPENSSL], [false])]
)

CHECK_MBEDTLS

AS_IF([test "x$have_crypto" = x],
	[AC_MSG_ERROR([No crypto library detected])])

AC_ARG_WITH([examples],
	AS_HELP_STRING([--with-examples], [Build example programs @<:@default=no@:>@]),
	[AM_CONDITIONAL([BUILD_EXAMPLES],[true])],
	[AM_CONDITIONAL([BUILD_EXAMPLES],[false])])

PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.10],
	[RPMB_CHECK="--with check"],[RPMB_CHECK="--without check"])

AC_SUBST([RPMBUILD_OPTS],["$RPMB_OPENSSL $RPMB_GNUTLS $RPMB_CHECK"])

dnl Check for compiler support flags
dnl AX_GCC_FUNC_ATTRIBUTE([deprecated])
dnl AX_GCC_FUNC_ATTRIBUTE([visibility])
AC_SUBST([GCC_FUNC_DEPRECATED],["__attribute__((__deprecated__))"])
AC_SUBST([GCC_EXPORT],["__attribute__((visibility(\"default\")))"])
AC_SUBST([GCC_NO_EXPORT],["__attribute__((visibility(\"hidden\")))"])
AC_SUBST([GCC_CONSTRUCTOR],["__attribute__((constructor))"])

dnl Valgrind defaults
AX_VALGRIND_DFLT([memcheck], [on])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

AX_CODE_COVERAGE

DX_ENV_APPEND(PROJECT_BRIEF, $PACKAGE_DESCRIPTION)
DX_INIT_DOXYGEN($PACKAGE_NAME, Doxyfile)

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	libjwt/Makefile
	examples/Makefile
	libjwt/libjwt.pc
	dist/Makefile
	dist/libjwt.spec
	tests/Makefile
	tests/keys/Makefile
	tests/keys/jwks/Makefile
	include/jwt_export.h
])

AC_OUTPUT
