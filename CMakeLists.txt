cmake_minimum_required(VERSION 3.10)
project(gekko C)
set(CMAKE_C_STANDARD 90)
###############################################################################
# OS specific configuration
###############################################################################
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    message(STATUS "OS: " ${CMAKE_SYSTEM_NAME})
else()
    message(FATAL_ERROR "Operating system not supported.")
endif()
###############################################################################
# Configure libssh2
###############################################################################
find_path(LIBSSH2_INC libssh2.h)
find_library(LIBSSH2_LIB NAMES ssh2 libssh2)

if (LIBSSH2_INC)
    message(STATUS "libssh2 include directory: " ${LIBSSH2_INC})
else()
    message(FATAL_ERROR "libssh2: include directory cannot be found.")
endif()

if (LIBSSH2_LIB)
    message(STATUS "libssh2 library directory: " ${LIBSSH2_LIB})
else()
    message(FATAL_ERROR "libssh2: library cannot be found.")
endif()
###############################################################################
# Add source files to project
###############################################################################
add_executable(gekko
    gekko.c
)
