# This file will be configured to contain variables for CPack. These variables
# should be set in the CMake list file of the project before CPack module is
# included. The list of available CPACK_xxx variables and their associated
# documentation may be obtained using
#  cpack --help-variable-list
#
# Some variables are common to all generators (e.g. CPACK_PACKAGE_NAME)
# and some are specific to a generator
# (e.g. CPACK_NSIS_EXTRA_INSTALL_COMMANDS). The generator specific variables
# usually begin with CPACK_<GENNAME>_xxxx.

set(CPACK_BINARY_TBZ2 "OFF")
set(CPACK_BINARY_DEB "ON")
set(CPACK_GENERATOR "TXZ")
set(CPACK_PACKAGE_VENDOR "maClara, LLC")
set(CPACK_SOURCE_GENERATOR "TXZ")
set(CPACK_SOURCE_TBZ2 "ON")
set(CPACK_SET_DESTDIR "ON")

set(CPACK_PACKAGE_CONTACT "Ben Collins <bcollins@ubuntu.com>")
set(CPACK_IGNORE_FILES "/\\.git/" "\\.gitignore" "\\.github/" "\\.swp\$" "\\.DS_Store")

string(TOLOWER ${CPACK_PACKAGE_NAME} CPACK_PACKAGE_NAME)
if (NOT ${CPACK_SOURCE_PACKAGE_FILE_NAME} EQUAL "")
	set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
else()
	set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-binary")
endif()
