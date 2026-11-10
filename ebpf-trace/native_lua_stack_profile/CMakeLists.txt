cmake_minimum_required(VERSION 3.16)
project(native_lua_stack_profile LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This profiling example targets Linux.")
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lua/lua.h")
    message(FATAL_ERROR "Initialize Lua first: git submodule update --init --recursive")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Lua core, auxiliary library, and standard libraries; no interpreter or tests.
add_library(lua SHARED
    lua/lapi.c
    lua/lcode.c
    lua/lctype.c
    lua/ldebug.c
    lua/ldo.c
    lua/ldump.c
    lua/lfunc.c
    lua/lgc.c
    lua/llex.c
    lua/lmem.c
    lua/lobject.c
    lua/lopcodes.c
    lua/lparser.c
    lua/lstate.c
    lua/lstring.c
    lua/ltable.c
    lua/ltm.c
    lua/lundump.c
    lua/lvm.c
    lua/lzio.c
    lua/lauxlib.c
    lua/lbaselib.c
    lua/ldblib.c
    lua/liolib.c
    lua/lmathlib.c
    lua/loslib.c
    lua/ltablib.c
    lua/lstrlib.c
    lua/lutf8lib.c
    lua/loadlib.c
    lua/lcorolib.c
    lua/linit.c
)
target_include_directories(lua PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lua")
target_compile_definitions(lua PRIVATE LUA_USE_LINUX)
target_link_libraries(lua PRIVATE m ${CMAKE_DL_LIBS})

add_executable(profile_test main.cpp lua_api.cpp)
target_link_libraries(profile_test PRIVATE lua)
target_compile_definitions(profile_test PRIVATE
    PROFILE_TEST_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/test.lua"
)
set_target_properties(profile_test PROPERTIES
    ENABLE_EXPORTS ON
    BUILD_RPATH "$ORIGIN"
)

# Use optimized code and debug information in every build type.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    foreach(target lua profile_test)
        target_compile_options(${target} PRIVATE
            -O2 -g
        )
    endforeach()
endif()
