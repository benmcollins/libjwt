# Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required (VERSION 3.7...3.15)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(LibJWTVersions)
include(GenerateExportHeader)

project(${LIBJWT_PROJECT}
	VERSION ${LIBJWT_VERSION}
	DESCRIPTION ${LIBJWT_DESCRIPTION}
	HOMEPAGE_URL ${LIBJWT_HOMEPAGE_URL}
	LANGUAGES C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

# Must be set after the above
include(GNUInstallDirs)

# Find all the things we need for the library
find_package(PkgConfig REQUIRED)

pkg_check_modules(JANSSON jansson>=2.0 REQUIRED IMPORTED_TARGET)

if (NOT DEFINED WITH_OPENSSL)
	set(OPENSSL_AUTO TRUE)
endif()
if (NOT DEFINED WITH_GNUTLS)
	set(GNUTLS_AUTO TRUE)
endif()
option(WITH_OPENSSL "Whether to use OpenSSL (default is auto detect)" ON)
option(WITH_GNUTLS "Whether to use GnuTLS (default is auto detect)" ON)

# option(WITH_MBEDTLS "Enable using MBedTLS (default is disabled)" ON)

option(WITH_EXAMPLES "Whether to build the example programs (default is OFF)" OFF)
option(WITH_TESTS "Whether to build and run the testsuite (default is ON)" ON)

# Need at least one of these
if (WITH_GNUTLS)
	if (NOT GNUTLS_AUTO)
		set(GNUTLS_REQUIRED REQUIRED)
	endif()
	# pkg_check_modules(GNUTLS gnutls>=3.6.0 IMPORTED_TARGET
	#		  ${GNUTLS_REQUIRED})
endif()

if (WITH_OPENSSL)
	if (NOT OPENSSL_AUTO)
		set(OPENSSL_REQUIRED REQUIRED)
	endif()
	pkg_check_modules(OPENSSL openssl>=1.1.0 IMPORTED_TARGET
			  ${OPENSSL_REQUIRED})
endif()

add_library(jwt SHARED)
add_library(jwt_static STATIC)
set_target_properties(jwt_static PROPERTIES
	OUTPUT_NAME jwt
	COMPILE_FLAGS -DJWT_STATIC_DEFINE)

set(JWT_SOURCES libjwt/base64.c
        libjwt/jwt-memory.c
        libjwt/jwt.c
        libjwt/jwks.c
        libjwt/jwt-setget.c
        libjwt/jwt-crypto-ops.c
        libjwt/jwt-validate.c
        libjwt/jwt-encode.c
        libjwt/jwt-verify.c)

# Allow building without deprecated functions (suggested)
option(EXCLUDE_DEPRECATED
	"Exclude deprecated parts of the library (default included)" FALSE)
if (EXCLUDE_DEPRECATED)
	set(NO_BUILD_DEPRECATED DEFINE_NO_DEPRECATED)
endif()

generate_export_header(jwt ${NO_BUILD_DEPRECATED})

include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}
		    ${CMAKE_SOURCE_DIR}/libjwt)

target_link_libraries(jwt PUBLIC PkgConfig::JANSSON)
target_link_libraries(jwt_static PUBLIC PkgConfig::JANSSON)

# Process the detected packages
set(HAVE_CRYPTO FALSE)
if (GNUTLS_FOUND)
	set(HAVE_CRYPTO TRUE)
        add_definitions(-DHAVE_GNUTLS)
	target_link_libraries(jwt PUBLIC PkgConfig::GNUTLS)
	target_link_libraries(jwt_static PUBLIC PkgConfig::GNUTLS)
	list(APPEND JWT_SOURCES
	     libjwt/gnutls/jwk-parse.c
	     libjwt/gnutls/sign-verify.c)
endif()

if (OPENSSL_FOUND)
	set(HAVE_CRYPTO TRUE)
	add_definitions(-DHAVE_OPENSSL)
	target_link_libraries(jwt PUBLIC PkgConfig::OPENSSL)
	target_link_libraries(jwt_static PUBLIC PkgConfig::OPENSSL)
	list(APPEND JWT_SOURCES
	     libjwt/openssl/jwk-parse.c
	     libjwt/openssl/sign-verify.c)
endif()

function(jwt_add_extra)
	set(oneValueArgs NAME SRC DIR)
	cmake_parse_arguments(Extra "" "${oneValueArgs}" "" ${ARGN})

	add_executable(${Extra_NAME} ${Extra_SRC})
	target_link_libraries(${Extra_NAME} PRIVATE jwt)
	set_target_properties(${Extra_NAME} PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY
		"${CMAKE_BINARY_DIR}/${Extra_DIR}")
endfunction()

function(jwt_add_tool)
	set(oneValueArgs NAME SRC DIR)
	cmake_parse_arguments(Tool "" "${oneValueArgs}" "" ${ARGN})

	add_executable(${Tool_NAME} ${Tool_SRC})
	target_link_libraries(${Tool_NAME}  PRIVATE jwt_static PkgConfig::OPENSSL)
	# target_link_libraries(${Tool_NAME} PRIVATE jwt)
	set_target_properties(${Tool_NAME} PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY
		"${CMAKE_BINARY_DIR}/tools")
	install(TARGETS ${Tool_NAME}
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endfunction()

if (WITH_EXAMPLES)
	jwt_add_extra(NAME jwtauth
		      SRC examples/main-auth.c
		      DIR examples)
	jwt_add_extra(NAME jwtgen
                      SRC examples/main-gen.c
                      DIR examples)
endif()

jwt_add_tool(NAME jwk2key
	      SRC tests/keys/jwks/jwk2key.c)
jwt_add_tool(NAME key2jwk
              SRC tests/keys/jwks/key2jwk.c)

# We need one of the things above to even work
if (NOT HAVE_CRYPTO)
	message(FATAL_ERROR "No crypto support detected")
endif()

target_sources(jwt PRIVATE ${JWT_SOURCES})
target_sources(jwt_static PRIVATE ${JWT_SOURCES})

target_include_directories(jwt PUBLIC
	$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

# Define versioning for the library (comes from configure.ac)
set_target_properties(jwt PROPERTIES
	VERSION ${LIBJWT_VERSION_INFO}
	SOVERSION ${LIBJWT_COMPATVERSION}
)

add_definitions(-D_GNU_SOURCE -O3 -Wall -Werror)
add_definitions(-DKEYDIR=\"${CMAKE_SOURCE_DIR}/tests/keys\")

# Install header
install(FILES include/jwt.h
	${CMAKE_BINARY_DIR}/jwt_export.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE README.md
	DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Install library
install(TARGETS jwt
	EXPORT ${LIBJWT_PROJECT}Targets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install Static library
install(TARGETS jwt_static
        EXPORT ${LIBJWT_PROJECT}StaticTargets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# For cmake users
install(EXPORT ${LIBJWT_PROJECT}Targets
	FILE ${LIBJWT_PROJECT}Config.cmake
	NAMESPACE ${LIBJWT_PROJECT}::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBJWT_PROJECT}
)

# For pkg-config users
unset(LIBJWT_LDFLAGS)
foreach (FLAG ${JANSSON_LDFLAGS} ${OPENSSL_LDFLAGS} ${GNUTLS_LDFLAGS})
	string(APPEND LIBJWT_LDFLAGS " " ${FLAG})
endforeach()

configure_file(libjwt/libjwt.pc.in libjwt.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libjwt.pc
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

find_package(Doxygen 1.12)

if (DOXYGEN_FOUND)
	set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/doxygen-doc)
	include(LibJWTDoxyfile)
	doxygen_add_docs(doxygen-doc ALL include/jwt.h)

	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doxygen-doc/man/man3/
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
		FILES_MATCHING PATTERN "man3/J*.3"
		PATTERN "man3/jw*.3")

	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doxygen-doc/html/
		DESTINATION  ${CMAKE_INSTALL_DOCDIR}/html/)
endif()

option(ENABLE_COVERAGE "Enable code coverage rules" OFF)

# Tests and coverage depend on this, but optional
if (WITH_TESTS)
	if (ENABLE_COVERAGE)
		set(CHECK_REQUIRED REQUIRED)
	endif()
	pkg_check_modules(CHECK check>=0.9.10 IMPORTED_TARGET ${CHECK_REQUIRED})
else()
	if (ENABLE_COVERAGE)
		message(SEND_ERROR "You must set WITH_TESTS=ON to enable code coverage")
	endif()
endif()

function(jwt_add_test)
	set(oneValueArgs NAME)
	cmake_parse_arguments(LibTest "" "${oneValueArgs}" "" ${ARGN})

	jwt_add_extra(NAME ${LibTest_NAME}
                      SRC tests/${LibTest_NAME}.c
                      DIR tests)

	target_link_libraries(${LibTest_NAME} PRIVATE PkgConfig::CHECK)
	add_test(NAME ${LibTest_NAME} COMMAND /bin/bash -c
		"export TEST=${LibTest_NAME}; . ${CMAKE_SOURCE_DIR}/tests/test-env.sh; exec ${CMAKE_BINARY_DIR}/tests/${LibTest_NAME}")
endfunction()

if (CHECK_FOUND)
	include(CTest)

	set (UNIT_TESTS jwt_dump jwt_ec jwt_encode jwt_grant jwt_header
		jwt_new jwt_rsa jwt_validate jwt_rsa_pss jwt_eddsa
		jwt_crypto jwt_es256k)

	if (OPENSSL_FOUND)
		# For now, only OpenSSL supports JWKS tests
		list (APPEND UNIT_TESTS jwt_jwks jwt_jwks_errors
			jwt_jwks_ec jwt_jwks_rsa)
	endif()

	foreach (TEST ${UNIT_TESTS})
		jwt_add_test(NAME ${TEST})
	endforeach()

	add_custom_target(check
		COMMAND ${CMAKE_CTEST_COMMAND}
		DEPENDS ${UNIT_TESTS})

	if (ENABLE_COVERAGE)
		set(CMAKE_BUILD_TYPE "Debug")
		include(CodeCoverage)
		append_coverage_compiler_flags()

		set(COVERAGE_LCOV_INCLUDES "${CMAKE_SOURCE_DIR}/libjwt/*.c")
		setup_target_for_coverage_lcov(
			NAME check-code-coverage
			OUTPUT "${PROJECT_NAME}-${PROJECT_VERSION}-coverage"
			TITLE "${PROJECT_NAME}-${PROJECT_VERSION} Code Coverage"
			EXECUTABLE ctest -j ${PROCESSOR_COUNT}
			DEPENDENCIES ${UNIT_TESTS})
	endif()
elseif(ENABLE_COVERAGE)
	message(SEND_ERROR "Coverage enabled, but did not find check library")
endif()

if (NOT ENABLE_COVERAGE)
	add_custom_target(check-code-coverage
		COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
			"Coverage needs to be enabled for this target (ENABLE_COVERAGE=YES)"
		VERBATIM)
endif()

set(CPACK_PROPERTIES_FILE "${CMAKE_SOURCE_DIR}/cmake/CPackConfig.cmake")
include(CPack)
