cmake_minimum_required(VERSION 3.13)

cmake_policy(SET CMP0076 NEW)

####################
# options
####################
option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)

if(NOT WIN32)
option(TARGET_RPATH "target rpath list (separator is ';') (default:@rpath;./)" OFF)
endif()

if(ENABLE_DEBUG)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
set(STACK_PROTECTOR_OPT  $<IF:$<CXX_COMPILER_ID:MSVC>,/GS,-fstack-check -fstack-protector>)
else()
set(STACK_PROTECTOR_OPT  "")
endif()

####################
# common setting
####################
set(WORK_WINDOWS_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
if(NOT CFD_DLC_OBJ_BINARY_DIR)
set(CFD_DLC_OBJ_BINARY_DIR   ${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME})
set(CFD_DLC_ROOT_BINARY_DIR
  $<IF:$<PLATFORM_ID:Windows>,${CFD_DLC_OBJ_BINARY_DIR},${CMAKE_BINARY_DIR}>)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CFD_DLC_OBJ_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CFD_DLC_OBJ_BINARY_DIR})

if(NOT CFD_DLC_SRC_ROOT_DIR)
set(CFD_DLC_SRC_ROOT_DIR   ${CMAKE_SOURCE_DIR})
endif()

if(NOT WIN32)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
endif()
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
set(CMAKE_INSTALL_RPATH "${TARGET_RPATH};./;@rpath")
else()
set(CMAKE_INSTALL_RPATH "./;@rpath")
endif()
endif()

####################
# cfd-dlc setting
####################
transform_makefile_srclist("Makefile.srclist" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake)

####################
# cfd-dlc test
####################
if(ENABLE_TESTS)
enable_testing()
include(CTest)
project(dlc_test CXX)

if(MSVC)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} /Od /Zi")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Od /Zi")
else()
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O0 -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
endif()

set(LIBWALLY_LIBRARY wally)
set(CFDCORE_LIBRARY cfdcore)
set(CFD_LIBRARY cfd)
set(CFD_DLC_LIBRARY cfddlc)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(WIN32 AND ENABLE_SHARED)
add_executable(${PROJECT_NAME} ${TEST_CFD_DLC_SOURCES})
else()
add_executable(${PROJECT_NAME} ${TEST_CFD_DLC_SOURCES} ${TEST_CFD_DLC_STATIC_SOURCES})
endif()

# using shared library : -DGTEST_LINKED_AS_SHARED_LIBRARY=1

if(ENABLE_SHARED)
target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /Wall 
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4668 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    CFDDLC_SHARED=1
    CFD_SHARED=1
    CFD_CORE_SHARED=1
)
else()
target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /Wall 
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4668 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
)
endif()

target_include_directories(${PROJECT_NAME}
  PRIVATE
    .
    ../src
    ${CFD_DLC_SRC_ROOT_DIR}/external/cfd-core/src/include
)

target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
)

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${LIBWALLY_LIBRARY}
    ${CFDCORE_LIBRARY}
    ${CFD_LIBRARY}
    ${CFD_DLC_LIBRARY}
    univalue
    gtest_main
    gmock
)


add_test(
  NAME ${PROJECT_NAME}
  COMMAND $<TARGET_FILE:${PROJECT_NAME}>
  WORKING_DIRECTORY ${CFD_DLC_OBJ_BINARY_DIR}
)

endif()		# ENABLE_TESTS
