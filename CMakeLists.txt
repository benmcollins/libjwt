project(libjwt C)

cmake_minimum_required(VERSION 2.8)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(LIBRARY_NAME jwt)

###############################################################################
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)# Static lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)# Shared lib
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)# executables

# Detect required packages
INCLUDE( FindPkgConfig )

find_package(OpenSSL REQUIRED)
find_package(Check)

PKG_SEARCH_MODULE( JANSSON jansson )

#Library used
set(LIBS ssl jansson crypto m pthread rt)

add_definitions(-DUSE_CMAKE)

include_directories(include)

add_library(${LIBRARY_NAME} SHARED libjwt/jwt.c)
add_library(${LIBRARY_NAME}_static STATIC libjwt/jwt.c)
set_target_properties(${LIBRARY_NAME}_static PROPERTIES OUTPUT_NAME ${LIBRARY_NAME})

target_link_libraries(${LIBRARY_NAME} ${LIBS})

install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME}_static
        LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        OPTIONAL)

install(FILES include/jwt.h DESTINATION "${CMAKE_INSTALL_PREFIX}/include/jwt")

if (CHECK_FOUND)
  enable_testing()
  add_custom_target(tests COMMAND ${CMAKE_CTEST_COMMAND} OPTIONAL)
  set(LIBS ${LIBS} check subunit)

  function(InitialiseTest test_name file)
      add_executable(${test_name} ${file})
      target_link_libraries(${test_name} ${LIBS} ${LIBRARY_NAME})
      add_test(NAME ${test_name} COMMAND ${test_name} OPTIONAL)
      add_dependencies(tests ${test_name})
  endfunction()

  InitialiseTest(jwt_dump tests/jwt_dump.c)
  InitialiseTest(jwt_encode tests/jwt_encode.c)
  InitialiseTest(jwt_grant tests/jwt_grant.c)
  InitialiseTest(jwt_new tests/jwt_new.c)
endif (CHECK_FOUND)
