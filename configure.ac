AC_PREREQ([2.61])
AC_INIT([libjwt], [1.0.0], [https://github.com/benmcollins/jwt/issues])
AM_INIT_AUTOMAKE
LT_PREREQ([2.2])
LT_INIT([])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([libjwt/config.h])

AC_SUBST([AM_CFLAGS], [-Wall])

CHECK_SSL

DX_MAN_FEATURE(ON)
DX_HTML_FEATURE(OFF)
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
	libjwt/libjwt.pc
])

AC_OUTPUT
