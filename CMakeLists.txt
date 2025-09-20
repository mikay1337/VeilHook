cmake_minimum_required (VERSION 3.30 FATAL_ERROR)

#==============================================================================
# C++ Standard
#==============================================================================
if (NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
endif()

project(
    VeilHook
    VERSION 0.0.1
    DESCRIPTION "Modern C++ Hook Library"
    LANGUAGES CXX
)

set(VEIL_HOOK_IS_MAIN_PROJECT PROJECT_IS_TOP_LEVEL)

#==============================================================================
# Project configuration
#==============================================================================
set(CMAKE_INSTALL_INCLUDEDIR include)
mark_as_advanced(${PROJECT_NAME}_FOUND)
mark_as_advanced(${PROJECT_NAME}_VERSION)
mark_as_advanced(${PROJECT_NAME}_DIR)

#==============================================================================
# Options
#==============================================================================
option(VEIL_HOOK_BUILD_SHARED "Build ${PROJECT_NAME} as shared library" OFF)
option(VEIL_HOOK_BUILD_TESTS "Build tests" ON)
option(VEIL_HOOK_BUILD_BENCHMARKS "Build benchmarks" OFF)
option(VEIL_HOOK_INSTALL "Install ${PROJECT_NAME}" ON)

#==============================================================================
# Dependencies
#==============================================================================
add_subdirectory(thirdparty)

#==============================================================================
# Static/Shared library
#==============================================================================
set(VEIL_HOOK_HEADERS 
    include/VeilHook.hpp
    include/VeilHook/version.hpp
    include/VeilHook/common.hpp
    include/VeilHook/utility.hpp
    include/VeilHook/allocator.hpp
    include/VeilHook/inline_hook.hpp
)
set(VEIL_HOOK_SRCS
    src/allocator.cpp
    src/windows.cpp
    src/inline_hook.cpp
)

if (VEIL_HOOK_BUILD_SHARED OR BUILD_SHARED_LIBS)
    add_library(${PROJECT_NAME} SHARED ${VEIL_HOOK_SRCS} ${VEIL_HOOK_HEADERS})
    target_compile_definitions(${PROJECT_NAME} PUBLIC VEIL_HOOK_SHARED)
else()
    add_library(${PROJECT_NAME} STATIC ${VEIL_HOOK_SRCS} ${VEIL_HOOK_HEADERS})
endif()

target_compile_definitions(${PROJECT_NAME} PUBLIC VEIL_HOOK_COMPILED_LIB)
target_link_libraries(${PROJECT_NAME} PUBLIC Zydis)
target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

#=============================================================================
# Generate clangd configuration
#=============================================================================
configure_file(.clangd.in ${CMAKE_SOURCE_DIR}/.clangd @ONLY)

#==============================================================================
# Tests
#==============================================================================
if (VEIL_HOOK_BUILD_TESTS OR BUILD_TESTING)
    enable_testing()
    include(cmake/snitch.cmake)
    add_subdirectory(tests)
endif()

#==============================================================================
# Benchmarks
#==============================================================================
#if (VEIL_HOOK_BUILD_BENCHMARKS)
#    add_subdirectory(benchmarks)
#endif()


#==============================================================================
# Installation
#==============================================================================
if (VEIL_HOOK_INSTALL)
    message(STATUS "Configuring installation of the project")

endif()