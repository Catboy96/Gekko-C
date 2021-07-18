########################################################################################################################
#   file:           CMakeLists.txt
#   description:    CMake configuration of Gekko
#   author:         (C) 2021 PlayerCatboy (Ralf Ren).
#   date:           Jul.17, 2021
########################################################################################################################
cmake_minimum_required(VERSION 3.10)
project(gekko C)
set(PROJECT_URL         "https://github.com/Catboy96/Gekko-C")
set(PROJECT_DESCRIPTION "Easy-peasy lizard-squeezy sync tool")
set(CMAKE_C_STANDARD 90)
########################################################################################################################
#   OS specific configuration
########################################################################################################################
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_definitions(-D DARWIN)
    message(STATUS      "OS: " ${CMAKE_SYSTEM_NAME})

    find_path(LIBSSH2_INC libssh2.h)
    find_library(LIBSSH2_LIB NAMES libssh2)

elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_definitions(-D WINDOWS)
    message(STATUS      "OS: " ${CMAKE_SYSTEM_NAME})

    set(LIBSSH2_INC ${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/libssh2/include)
    set(LIBSSH2_LIB ${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/libssh2/bin/libssh2.dll)

else()
    message(FATAL_ERROR "Operating system not supported.")
endif()
########################################################################################################################
#   libssh2
########################################################################################################################
if (LIBSSH2_INC)
    message(STATUS      "libssh2 include directory: " ${LIBSSH2_INC})
else()
    message(FATAL_ERROR "libssh2: include directory cannot be found.")
endif()

if (LIBSSH2_LIB)
    message(STATUS      "libssh2 library path:      " ${LIBSSH2_LIB})
else()
    message(FATAL_ERROR "libssh2: library cannot be found.")
endif()
########################################################################################################################
#   Compiler settings
########################################################################################################################
add_definitions(
    -D GEKKO_DEBUG
)

add_compile_options(
    -O2 -Wall
)
########################################################################################################################
#   Linker settings
########################################################################################################################
include_directories(
    ${LIBSSH2_INC}
)

link_libraries(
    ${LIBSSH2_LIB}
)
########################################################################################################################
#   Add source files to project
########################################################################################################################
add_executable(gekko
    gekko.c
)
########################################################################################################################
#   End
########################################################################################################################