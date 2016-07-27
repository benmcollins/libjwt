# Copyright 2016 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
cmake_minimum_required(VERSION 2.8.7)
project(jwt)
include(ExternalProject)
enable_testing()
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/_install)
set(PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/_prefix)
set(PATCHES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/patches)
set(INCLUDE_DIR ${INSTALL_DIR}/include)
set(LIBRARY_DIR ${INSTALL_DIR}/lib${LIB_SUFFIX})
set(JWT_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/../include)
set(JWT_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/../libjwt)
set(JWT_TEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/../tests)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
#find_package (Threads)
# base64 external dependency
ExternalProject_Add(jansson
PREFIX ${PREFIX_DIR}/jansson
GIT_REPOSITORY https://github.com/akheron/jansson
GIT_TAG "master"
CMAKE_ARGS += -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
)
add_library(libjansson STATIC IMPORTED)
add_dependencies(libjansson jansson)

set(SOURCES ${JWT_SRC_DIR}/jwt.c)

add_library(libjwt STATIC ${SOURCES})

include_directories(
${JWT_INCLUDE_DIR}
${JWT_SRC_DIR}
${INCLUDE_DIR}
${INCLUDE_DIR}/jansson
)
include_directories (SYSTEM /usr/include)
message (STATUS "C FLAGS: ${CMAKE_C_FLAGS}")
link_directories ( ${LIBRARY_DIR} )
add_definitions(-std=c99)

add_subdirectory (tests)

