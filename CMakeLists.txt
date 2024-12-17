cmake_minimum_required (VERSION 3.7...3.15)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Extract info from configure.ac
include(AutoToolsVersion)

project(${LIBJWT_PROJECT} VERSION ${LIBJWT_VERSION} LANGUAGES C)
set(CMAKE_C_FLAGS -Wall)

# Find all the things we need for the library
find_package(PkgConfig REQUIRED)

pkg_check_modules(JANSSON jansson>=2.0 REQUIRED)

# Need at least one of these
pkg_check_modules(GNUTLS gnutls>=3.6.0)
pkg_check_modules(OPENSSL openssl>=1.1.0)

# Tests and coverage depend on this, but optional
pkg_check_modules(CHECK check>=0.9.4)

add_library(jwt SHARED)
add_library(jwt_static STATIC)
set_target_properties(jwt_static PROPERTIES OUTPUT_NAME jwt)

target_sources(jwt PRIVATE libjwt/jwt.c libjwt/jwks.c libjwt/base64.c)

include_directories(${CMAKE_SOURCE_DIR}/include)

target_link_libraries(jwt PRIVATE ${JANSSON_LINK_LIBRARIES})
target_include_directories(jwt PRIVATE
	${JANSSON_INCLUDE_DIRS})

# Process the detected packages

if (GNUTLS_FOUND)
	set(HAVE_CRYPTO 1)
        add_definitions(-DHAVE_GNUTLS)
	target_link_libraries(jwt PRIVATE ${GNUTLS_LINK_LIBRARIES})
	target_include_directories(jwt PRIVATE
		${GNUTLS_INCLUDE_DIRS})
	target_sources(jwt PRIVATE libjwt/jwt-gnutls.c libjwt/jwks-gnutls.c)
endif()

if (OPENSSL_FOUND)
	set(HAVE_CRYPTO 1)
	add_definitions(-DHAVE_OPENSSL)
	target_link_libraries(jwt PRIVATE ${OPENSSL_LINK_LIBRARIES})
	target_include_directories(jwt PRIVATE
		${OPENSSL_INCLUDE_DIRS})
	target_sources(jwt PRIVATE libjwt/jwt-openssl.c libjwt/jwks-openssl.c)
endif()

# We need one of the things above to even work
if (NOT HAVE_CRYPTO)
	message(FATAL_ERROR "No crypto support detected")
endif()

# Setup the static library by copying shared lib
get_target_property(STATIC_LINK_LIBRARIES jwt LINK_LIBRARIES)
get_target_property(STATIC_INCLUDE_DIRECTORIES jwt INCLUDE_DIRECTORIES)
get_target_property(STATIC_SOURCES jwt SOURCES)

target_sources(jwt_static PRIVATE ${STATIC_SOURCES})
target_link_libraries(jwt_static PRIVATE ${STATIC_LINK_LIBRARIES})
target_include_directories(jwt_static PRIVATE ${STATIC_INCLUDE_DIRECTORIES})

target_include_directories(jwt PUBLIC
	$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

# Define versioning for the library (comes from configure.ac)
set_target_properties(jwt PROPERTIES
	VERSION ${LIBJWT_VERSION_INFO}
	SOVERSION ${LIBJWT_COMPATVERSION}
)

add_definitions(-D_GNU_SOURCE)
add_definitions(-DKEYDIR=\"${CMAKE_SOURCE_DIR}/tests/keys\")

# Install header
install(FILES include/jwt.h DESTINATION include)

# Install library
install(TARGETS jwt
	EXPORT ${LIBJWT_PROJECT}Targets
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)

# Install Static library
install(TARGETS jwt_static
        EXPORT ${LIBJWT_PROJECT}StaticTargets
        ARCHIVE DESTINATION lib
)

install(EXPORT ${LIBJWT_PROJECT}Targets
	FILE ${LIBJWT_PROJECT}Config.cmake
	NAMESPACE ${LIBJWT_PROJECT}::
	DESTINATION lib/cmake/${LIBJWT_PROJECT}
)

# We do this to make it compatible with autotools
set(PACKAGE_NAME ${PROJECT_NAME})
set(PACKAGE_VERSION ${PROJECT_VERSION})
set(prefix ${CMAKE_INSTALL_PREFIX})
string(REGEX REPLACE ";" " " JANSSON_LIBS "${JANSSON_LDFLAGS}")
string(REGEX REPLACE ";" " " OPENSSL_LIBS "${OPENSSL_LDFLAGS}")
string(REGEX REPLACE ";" " " GNUTLS_LIBS "${GNUTLS_LDFLAGS}")
configure_file(libjwt/libjwt.pc.in libjwt.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libjwt.pc DESTINATION lib/pkgconfig)

find_package(Doxygen)
if (DOXYGEN_FOUND)
	doxygen_add_docs(doxygen-doc
		libjwt libjwt include
		CONFIG_FILE ${CMAKE_SOURCE_DIR}/doxygen.cfg
		COMMENT "Generating API documentation with Doxygen")
	set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/html")
endif()

option(ENABLE_COVERAGE "Enable code coverage rules" OFF)

if (CHECK_FOUND)
	enable_testing()

	set (TARGET_NAMES jwt_dump jwt_ec jwt_encode jwt_grant jwt_header
		jwt_new jwt_rsa jwt_validate jwt_rsa_pss jwt_eddsa
		jwt_crypto jwt_es256k)

	if (OPENSSL_FOUND)
		# For now, only OpenSSL supports JWKS tests
		list (APPEND TARGET_NAMES jwt_jwks jwt_jwks_errors
			jwt_jwks_ec jwt_jwks_rsa)
	endif()

	foreach (TARGET_NAME ${TARGET_NAMES})
		add_executable(${TARGET_NAME} tests/${TARGET_NAME}.c)
		target_link_libraries(${TARGET_NAME} PRIVATE jwt)
		target_link_libraries(${TARGET_NAME} PRIVATE ${CHECK_LINK_LIBRARIES})
		target_include_directories(${TARGET_NAME} PRIVATE ${CHECK_INCLUDE_DIRS})
		add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
	endforeach()

	if (ENABLE_COVERAGE)
		set(CMAKE_BUILD_TYPE "Debug")
		include(CodeCoverage)
		append_coverage_compiler_flags()

		setup_target_for_coverage_lcov(
			NAME coverage
			OUTPUT "${PROJECT_NAME}-${PROJECT_VERSION}-coverage"
			TITLE "${PROJECT_NAME}-${PROJECT_VERSION} Code Coverage"
			EXECUTABLE ctest -j ${PROCESSOR_COUNT}
			DEPENDENCIES ${TARGET_NAMES}
			EXCLUDE "tests/*" "**/ll.h" "/usr/**")
	endif()
endif()
