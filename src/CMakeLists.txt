cmake_minimum_required(VERSION 3.13)

cmake_policy(SET CMP0076 NEW)

####################
# options
####################

if(NOT WIN32)
#option(TARGET_RPATH "target rpath list (separator is ';') (default:)" "")
set(TARGET_RPATH "" CACHE STRING "target rpath list (separator is ';') (default:)")
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
option(ENABLE_RPATH "enable rpath (ON or OFF. default:ON)" ON)
else()
set(TARGET_RPATH "")
set(ENABLE_RPATH off)
set(ENABLE_COVERAGE FALSE)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
set(ENABLE_DEBUG  TRUE)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
if(ENABLE_COVERAGE)
set(STACK_PROTECTOR_OPT  "")
else()
set(STACK_PROTECTOR_OPT  $<IF:$<CXX_COMPILER_ID:MSVC>,/GS,-fstack-check -fstack-protector>)
endif()
else()
set(ENABLE_DEBUG  FALSE)
set(STACK_PROTECTOR_OPT  "")
endif() # CMAKE_BUILD_TYPE

####################
# common setting
####################
set(WORK_WINDOWS_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
if(NOT CFD_DLC_OBJ_BINARY_DIR)
set(CFD_DLC_OBJ_BINARY_DIR   ${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME})
set(CFD_DLC_ROOT_BINARY_DIR  ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CFD_DLC_OBJ_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CFD_DLC_OBJ_BINARY_DIR}) # for linux
endif()

if(NOT WIN32)
if(ENABLE_RPATH)
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
else()
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
endif()
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
if(APPLE)
string(REPLACE "\$\$ORIGIN" "." TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\$ORIGIN" "." TEMP_RPATH2 "${TEMP_RPATH1}")
string(REPLACE "\$\${ORIGIN}" "." TEMP_RPATH3 "${TEMP_RPATH2}")
string(REPLACE "\${ORIGIN}" "." MODIFIED_RPATH "${TEMP_RPATH3}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};./;./build/${RPATH_TARGET};@rpath")
else()
string(REPLACE "\$\${ORIGIN}" "$$ORIGIN" TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\${ORIGIN}" "$ORIGIN" MODIFIED_RPATH "${TEMP_RPATH1}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};$ORIGIN/;./;./build/${RPATH_TARGET};@rpath")
endif()
else(TARGET_RPATH)
if(APPLE)
set(CMAKE_INSTALL_RPATH "./;./build/${RPATH_TARGET};@rpath")
else()
set(CMAKE_INSTALL_RPATH "$ORIGIN/;./;./build/${RPATH_TARGET};@rpath")
endif()
endif(TARGET_RPATH)
else()
set(CMAKE_SKIP_BUILD_RPATH  TRUE)
endif()
endif()

if(ENABLE_DEBUG AND ENABLE_COVERAGE)
set(COLLECT_COVERAGE ON)
set(PROFILE_ARCS_OPT -fprofile-arcs)
set(TEST_COVERAGE_OPT -ftest-coverage)
set(GCOV_LIBRARY gcov)
set(COVERAGE 1)
else()
set(PROFILE_ARCS_OPT  "")
set(TEST_COVERAGE_OPT "")
set(GCOV_LIBRARY  "")
endif()


####################
# cfddlc setting
####################
transform_makefile_srclist("Makefile.srclist" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake)

if(NOT CFDDLC_DEBUG)
set(CFDDLC_DEBUG_OPT "")
else()
set(CFDDLC_DEBUG_OPT  CFDDLC_DEBUG)
endif()

if(NOT CFDDLC_LOG_CONSOLE)
set(CFDDLC_LOG_CONSOLE_OPT "")
else()
set(CFDDLC_LOG_CONSOLE_OPT  CFDDLC_LOG_CONSOLE)
endif()

set(USE_SCALAR_4X64 true)

####################
# cfddlc
####################
project(cfddlc CXX)
# set(LIBRARY_PREFIX $<IF:$<PLATFORM_ID:Windows>,,lib>)
# set(LIBRARY_SUFFIX $<IF:$<PLATFORM_ID:Windows>,dll,$<IF:$<PLATFORM_ID:Darwin>,dylib,so>>)

if(MSVC)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi")
else()
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# search cfd with PkgConfig.
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
pkg_check_modules(LIBCFD cfd)
if(NOT CFD_FOUND)
set(CFD_INSTALLED   FALSE)
else()  # PkgConfig
set(CFD_INSTALLED   ${CFD_FOUND})
endif()
else()
set(CFD_INSTALLED   OFF)
endif()

if(WIN32 OR (NOT ${CFD_INSTALLED}))
set(USE_INSTALLED_LIBRARY  FALSE)
set(LIBWALLY_LIBRARY wally)
set(CFD_LIBRARY cfd)
set(CFDCORE_LIBRARY cfdcore)
set(INSTALLED_LIBRARY_DIR "")
set(INSTALLED_INCLUDE_DIR "./")
else()
set(USE_INSTALLED_LIBRARY  TRUE)
pkg_check_modules(WALLY     REQUIRED wally)
pkg_check_modules(CFDCORE   REQUIRED cfd-core)
pkg_check_modules(LIBUNIVALUE  REQUIRED libunivalue)
set(CFD_LIBRARY ${CFD_LIBRARIES})
set(CFDCORE_LIBRARY ${CFDCORE_LIBRARIES})
set(LIBWALLY_LIBRARY ${WALLY_LIBRARIES})
set(UNIVALUE_LIBRARY ${LIBUNIVALUE_LIBRARIES})

set(INSTALLED_LIBRARY_DIR ${CFD_LIBRARY_DIRS})
set(INSTALLED_INCLUDE_DIR ${CFD_INCLUDE_DIRS})
message(STATUS "[INSTALLED_LIBRARY_DIR]=${INSTALLED_LIBRARY_DIR}")
message(STATUS "[INSTALLED_INCLUDE_DIR]=${INSTALLED_INCLUDE_DIR}")
endif() # WIN32 OR (NOT ${CFDJS_API_FOUND})

if(ENABLE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()
target_sources(${PROJECT_NAME}
  PRIVATE
    ${CFDDLC_SOURCES}
)

target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /LD
      /source-charset:utf-8 /Wall
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)

if(ENABLE_SHARED)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    CFD_DLC_BUILD=1
    CFD_SHARED=1
    CFD_CORE_SHARED=1
)
else()
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    CFD_DLC_BUILD=1
)
endif()

target_include_directories(${PROJECT_NAME}
  PUBLIC
    ../include
  PRIVATE
    .
    include
    ${INSTALLED_INCLUDE_DIR}
)

target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
    ${INSTALLED_LIBRARY_DIR}
)

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${LIBWALLY_LIBRARY}
    ${CFD_LIBRARY}
    ${CFDCORE_LIBRARY}
    ${GCOV_LIBRARY}
)


####################
# coverage
####################
if(ENABLE_DEBUG AND ENABLE_COVERAGE)
add_custom_target(
  lcov_cfddlc1 ${CMAKE_COMMAND} -E make_directory ${CFD_DLC_ROOT_BINARY_DIR}/lcov_cfddlc_output
  COMMAND lcov -c -d . -o cfddlc1.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cfddlc.dir
)
#  COMMAND gcov -f -m *.gcda > console.log
add_custom_target(
  lcov_cfddlc lcov -e cfddlc1.info "*/cfddlc_*" -o cfddlc.info
  COMMAND genhtml -s --demangle-cpp -o ${CFD_DLC_ROOT_BINARY_DIR}/lcov_cfddlc_output cfddlc.info
  DEPENDS lcov_cfddlc1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cfddlc.dir
)
endif()
# lcov -c -d . -o cfddlc1.info
# lcov -e cfddlc1.info "*/cfddlc_*" -o cfddlc.info
# genhtml -s --demangle-cpp -o output cfddlc.info


####################
# install & export
####################
include(GNUInstallDirs)

install(TARGETS       ${PROJECT_NAME}
        EXPORT        ${PROJECT_NAME}-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
# https://cmake.org/cmake/help/latest/command/install.html

export(TARGETS ${PROJECT_NAME}
       APPEND FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-export.cmake
       EXPORT_LINK_INTERFACE_LIBRARIES)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/cfddlc"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.h")
