# Source of truth

set(LIBJWT_PROJECT		"LibJWT")
set(LIBJWT_DESCRIPTION		"The C JSON Web Token Library +JWK +JWKS")
set(LIBJWT_HOMEPAGE_URL		"https://libjwt.io")

set(LIBJWT_VERSION_SET		3 2 0)

set(LIBJWT_SO_CRA		16 0 2)
# SONAME History
# v1.12.1      0 => 1
# v1.15.0      1 => 2
# v3.0.0       2 => 14
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

string(TOLOWER ${LIBJWT_PROJECT} LIBJWT_PROJECT_LOWER)
list(GET LIBJWT_VERSION_SET 0 DEFINE_MAJOR)
list(GET LIBJWT_VERSION_SET 1 DEFINE_MINOR)
list(GET LIBJWT_VERSION_SET 2 DEFINE_MICRO)
string(JOIN "." LIBJWT_VERSION ${LIBJWT_VERSION_SET})
set(DEFINE_VERSION "\"${LIBJWT_VERSION}\"")

list(GET LIBJWT_SO_CRA 0 LIBJWT_SO_CURRENT)
list(GET LIBJWT_SO_CRA 1 LIBJWT_SO_REVISION)
list(GET LIBJWT_SO_CRA 2 LIBJWT_SO_AGE)

# Libtool does -version-info cur:rev:age, but cmake does things
# a bit different. However, the result is the same.
math(EXPR JWT_SO_MAJOR "${LIBJWT_SO_CURRENT} - ${LIBJWT_SO_AGE}")
set(LIBJWT_VERSION_INFO "${JWT_SO_MAJOR}.${LIBJWT_SO_AGE}.${LIBJWT_SO_REVISION}")
set(LIBJWT_COMPATVERSION "${JWT_SO_MAJOR}")
