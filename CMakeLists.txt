project(libjwt C)

cmake_minimum_required(VERSION 2.8)

set(LIBRARY_NAME jwt)

# XXX Update this in libjwt/Makefile.am as well
set(LIBJWT_VERSION_MAJOR 0)
set(LIBJWT_VERSION_MINOR 3)
set(LIBJWT_VERSION_PATCH 0)
set(LIBJWT_VERSION_STRING ${LIBJWT_VERSION_MAJOR}.${LIBJWT_VERSION_MINOR}.${LIBJWT_VERSION_PATCH})

###############################################################################
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)# Static lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)# Shared lib
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)# executables

# Detect required packages
INCLUDE( FindPkgConfig )

PKG_SEARCH_MODULE (OPENSSL REQUIRED openssl)
PKG_SEARCH_MODULE (JANSSON REQUIRED jansson)
PKG_SEARCH_MODULE (CHECK check)

add_definitions(-DUSE_CMAKE)

include_directories(include ${OPENSSL_INCLUDE_DIRS} ${JANSSON_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARY_DIRS} ${JANSSON_LIBRARY_DIRS})

add_library(${LIBRARY_NAME} SHARED libjwt/jwt.c)
add_library(${LIBRARY_NAME}_static STATIC libjwt/jwt.c)
set_target_properties(${LIBRARY_NAME}_static PROPERTIES OUTPUT_NAME ${LIBRARY_NAME})
set_target_properties(${LIBRARY_NAME} PROPERTIES VERSION ${LIBJWT_VERSION_STRING}
                      SOVERSION ${LIBJWT_VERSION_MAJOR})

# Check if _GNU_SOURCE is available.
CHECK_SYMBOL_EXISTS(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

if (_GNU_SOURCE)
  add_definitions(-D_GNU_SOURCE)
endif()

set (LIBS ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})

target_link_libraries(${LIBRARY_NAME} ${LIBS})

install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME}_static
        LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        OPTIONAL)

install(FILES include/jwt.h DESTINATION "${CMAKE_INSTALL_PREFIX}/include/jwt")

if (CHECK_FOUND)
  include_directories(${CHECK_INCLUDE_DIRS})
  link_directories(${CHECK_LIBRARY_DIRS})
  add_definitions(${CHECK_CFLAGS_OTHER} -DKEYDIR="${PROJECT_SOURCE_DIR}/tests/keys")

  enable_testing()
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} OPTIONAL)

  function(InitialiseTest test_name file)
      add_executable(${test_name} ${file})
      target_link_libraries(${test_name} ${LIBS} ${LIBRARY_NAME}
		${CHECK_LIBRARIES} ${CHECK_LDFLAGS})
      add_test(NAME ${test_name} COMMAND ${test_name} OPTIONAL)
      add_dependencies(check ${test_name})
  endfunction()

  InitialiseTest(jwt_dump tests/jwt_dump.c)
  InitialiseTest(jwt_encode tests/jwt_encode.c)
  InitialiseTest(jwt_grant tests/jwt_grant.c)
  InitialiseTest(jwt_new tests/jwt_new.c)
  InitialiseTest(jwt_rsa tests/jwt_rsa.c)
  InitialiseTest(jwt_ec tests/jwt_ec.c)
endif (CHECK_FOUND)
