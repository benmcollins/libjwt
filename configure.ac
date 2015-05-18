AC_PREREQ([2.61])
AC_INIT([libjwt], [1.0.0], [https://github.com/benmcollins/jwt/issues])
AM_INIT_AUTOMAKE
LT_PREREQ([2.2])
LT_INIT([])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([libjwt/config.h])

AC_SUBST([AM_CFLAGS], [-Wall])

CHECK_SSL

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	libjwt/Makefile
	examples/Makefile
])

AC_OUTPUT
