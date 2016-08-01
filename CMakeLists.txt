project(libjwt C CXX)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Ofast -Wextra -pedantic -fPIE")

set(LIBRARY_NAME jwt)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)# Static lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)# Shared lib
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)# executables

#Library used
set(LIBS ssl crypto jansson check m pthread rt subunit)

add_definitions(-DUSE_CMAKE)

include_directories(include)

set(SOURCES libjwt/jwt.c)

add_library(${LIBRARY_NAME} SHARED ${SOURCES})
add_library(${LIBRARY_NAME}_static STATIC ${SOURCES})
set_target_properties(${LIBRARY_NAME}_static PROPERTIES OUTPUT_NAME ${LIBRARY_NAME})

target_link_libraries(${LIBRARY_NAME} ${LIBS})

install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME}_static
        LIBRARY DESTINATION /usr/lib
        ARCHIVE DESTINATION /usr/lib
        OPTIONAL)

install(FILES include/jwt.h DESTINATION "/usr/include/jwt")

add_subdirectory(tests)