# Get information from configure.ac
FILE(STRINGS "${CMAKE_SOURCE_DIR}/configure.ac" configure REGEX "^m4_define")
foreach (line ${configure})
    foreach (var major_version minor_version micro_version
		so_current so_revision so_age libjwt_project
		libjwt_bugs libjwt_url libjwt_brief)
	if (NOT ${var} AND line MATCHES "m4_define\\(\\[${var}\\],.*\\[(.*)\\]\\)")
            set(${var} "${CMAKE_MATCH_1}")
            break()
        endif()
    endforeach()
endforeach()

set(LIBJWT_VERSION "${major_version}.${minor_version}.${micro_version}")
set(LIBJWT_PROJECT "${libjwt_project}")
set(LIBJWT_DESCRIPTION "${libjwt_brief}")
set(LIBJWT_HOMEPAGE_URL "${libjwt_url}")

# WWLTD (What would libtool do)
math(EXPR SO_MAJOR "${so_current} - ${so_age}")
set(SO_MINOR "${so_age}")
set(SO_REVISION "${so_revision}")
set(LIBJWT_VERSION_INFO "${SO_MAJOR}.${SO_MINOR}.${SO_REVISION}")
set(LIBJWT_COMPATVERSION "${SO_MAJOR}")
