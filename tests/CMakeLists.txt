include(FindPkgConfig)

pkg_check_modules(CHECK check>=0.9.10 REQUIRED IMPORTED_TARGET)

enable_testing ()

# Add the check target to behave like automake
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

set (TARGET_NAMES jwt_dump jwt_ec jwt_encode jwt_grant jwt_header jwt_new jwt_rsa jwt_validate)

if (UNIX)
	set (PLATFORM_LIBRARIES pthread)
endif ()

foreach (TARGET_NAME ${TARGET_NAMES})
	add_executable (${TARGET_NAME} ${TARGET_NAME}.c)
	target_link_libraries(${TARGET_NAME} PRIVATE PkgConfig::CHECK jwt)
	target_compile_definitions (${TARGET_NAME} PRIVATE KEYDIR=\"${CMAKE_CURRENT_SOURCE_DIR}/keys\" _GNU_SOURCE)
	add_test (${TARGET_NAME} ${TARGET_NAME})
endforeach ()
