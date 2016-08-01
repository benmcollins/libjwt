enable_testing()
add_custom_target(tests COMMAND ${CMAKE_CTEST_COMMAND})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(LIBS "${LIBS} -lbenchmark")

function(InitialiseTest test_name file)
    add_executable(${test_name} ${file})
    target_link_libraries(${test_name} ${LIBS} ${LIBRARY_NAME})
    add_test(NAME ${test_name}
            COMMAND ${PROJECT_SOURCE_DIR}/bin/${test_name})
    add_custom_command(TARGET ${test_name}
            POST_BUILD
            COMMAND ${PROJECT_SOURCE_DIR}/bin/${test_name} --benchmark_min_time=0.01
            DEPENDS tests
            COMMENT "Execute ${test_name} test.")
endfunction()

InitialiseTest(jwt_dump jwt_dump.c)
InitialiseTest(jwt_encode jwt_encode.c)
InitialiseTest(jwt_grant jwt_grant.c)
InitialiseTest(jwt_new jwt_new.c)
InitialiseTest(benchmark benchmark.cc)
