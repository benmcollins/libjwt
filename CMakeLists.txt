cmake_minimum_required(VERSION 3.8)
project(jwt)

set(CMAKE_C_STANDARD 99)

include_directories(include)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${JANSSON_HOME}/src)

set(SOURCE_FILES
        include/jwt.h
        libjwt/base64.c
        libjwt/base64.h
        libjwt/jwt.c
        libjwt/jwt-openssl.c
        libjwt/jwt-private.h)

add_library(jwt ${SOURCE_FILES})
