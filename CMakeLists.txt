cmake_minimum_required (VERSION 3.7...3.15)

project(LibJWT VERSION 2.1.0 LANGUAGES C)

add_library(jwt SHARED libjwt/jwt.c libjwt/jwks.c libjwt/base64.c)

include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GNUTLS gnutls>=3.6.0)
pkg_check_modules(OPENSSL openssl>=1.1.0)
pkg_check_modules(JANSSON jansson>=2.0 REQUIRED)
pkg_check_modules(CHECK check)

target_link_libraries(jwt PRIVATE ${JANSSON_LINK_LIBRARIES})
target_include_directories(jwt PRIVATE
	${JANSSON_INCLUDE_DIRS})

if (GNUTLS_FOUND)
        add_definitions(-DHAVE_GNUTLS)
	target_link_libraries(jwt PRIVATE ${GNUTLS_LINK_LIBRARIES})
	target_include_directories(jwt PRIVATE
		${GNUTLS_INCLUDE_DIRS})
	target_sources(jwt PRIVATE libjwt/jwt-gnutls.c libjwt/jwks-gnutls.c)
endif ()

if (OPENSSL_FOUND)
	add_definitions(-DHAVE_OPENSSL)
	target_link_libraries(jwt PRIVATE ${OPENSSL_LINK_LIBRARIES})
	target_include_directories(jwt PRIVATE
		${OPENSSL_INCLUDE_DIRS})
	target_sources(jwt PRIVATE libjwt/jwt-openssl.c libjwt/jwks-openssl.c)
endif ()

target_include_directories(jwt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Define versioning for the library
set_target_properties(jwt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 2
)

add_definitions(-D_GNU_SOURCE)
add_definitions(-DKEYDIR=\"${CMAKE_SOURCE_DIR}/tests/keys\")

install(DIRECTORY include/ DESTINATION include)

# Installation rules
install(TARGETS jwt
	EXPORT LibJWTTargets
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)

# Install headers
install(DIRECTORY include/ DESTINATION include)

install(EXPORT LibJWTTargets
	FILE LibJWTConfig.cmake
	NAMESPACE LibJWT::
	DESTINATION lib/cmake/LibJWT
)

if (CHECK_FOUND)
	enable_testing()

	set (TARGET_NAMES jwt_dump jwt_ec jwt_encode jwt_grant jwt_header jwt_new
		jwt_rsa jwt_validate jwt_rsa_pss jwt_eddsa jwt_crypto jwt_es256k)

	foreach (TARGET_NAME ${TARGET_NAMES})
		add_executable(${TARGET_NAME} tests/${TARGET_NAME}.c)
		target_link_libraries(${TARGET_NAME} PRIVATE jwt)
		target_link_libraries(${TARGET_NAME} PRIVATE ${CHECK_LINK_LIBRARIES})
		target_include_directories(${TARGET_NAME} PRIVATE ${CHECK_INCLUDE_DIRS})
		add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
	endforeach ()

	if(ENABLE_COVERAGE)
		if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
			message(STATUS "Code coverage enabled")
			add_compile_options(--coverage -O0 -g)
			add_link_options(--coverage)
		else()
			message(FATAL_ERROR "Code coverage only supported with GCC or Clang")
		endif()

		find_program(LCOV lcov)
		find_program(GENHTML genhtml)

		if(LCOV AND GENHTML)
			add_custom_target(coverage
			COMMAND ${LCOV} --capture --directory . --output-file
				coverage.info --rc lcov_branch_coverage=1
			COMMAND ${LCOV} --remove coverage.info '*/tests/*'
				'*/usr/include/*' --output-file coverage.info
				--rc lcov_branch_coverage=1
			COMMAND ${GENHTML} coverage.info --output-directory coverage
				--rc lcov_branch_coverage=1
			COMMAND ${CMAKE_COMMAND} -E echo
				"Coverage report generated in" 
				${CMAKE_BINARY_DIR}/coverage/index.html
			DEPENDS ${TARGET_NAMES}
			)
		else()
			message(WARNING "lcov or genhtml missing")
		endif()
	endif()
endif()
