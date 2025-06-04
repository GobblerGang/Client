cmake_minimum_required(VERSION 3.27)

# Enable vcpkg toolchain on Windows if available (must be before project())
if(WIN32 AND DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
    message(STATUS "Using vcpkg toolchain: ${CMAKE_TOOLCHAIN_FILE}")
elseif(WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(WARNING "VCPKG_ROOT environment variable not set. Ensure vcpkg is integrated.")
endif()

project(CPlusPlusClient)

# Allow local configuration overrides
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
    add_compile_options(
            -Wno-deprecated-declarations
            -Wno-c++20-extensions
            -Wno-c++26-extensions
    )
elseif(MSVC)
    add_compile_options(/wd4996)
endif()

# Find Qt6 (try both paths)
if(NOT Qt6_DIR)
    set(Qt6_DIR "" CACHE PATH "Path to Qt6 CMake directory")
endif()
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# Find other dependencies
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)

# Platform-specific Argon2 handling
if(WIN32)
    # Windows - use vcpkg
    find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
    find_library(ARGON2_LIBRARY NAMES argon2 libargon2)
    if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
        message(FATAL_ERROR "Argon2 not found. Install with: vcpkg install argon2")
    endif()
else()
    # macOS/Unix - use pkg-config or system paths
    find_package(PkgConfig)
    pkg_check_modules(ARGON2 IMPORTED_TARGET libargon2)

    if(NOT ARGON2_FOUND)
        # Fallback to manual find
        find_library(ARGON2_LIBRARY NAMES argon2)
        find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
        if(NOT ARGON2_LIBRARY OR NOT ARGON2_INCLUDE_DIR)
            message(FATAL_ERROR "Argon2 not found. Install with: brew install argon2")
        endif()
    endif()
endif()

# Source and header files (combined from both versions)
file(GLOB_RECURSE SOURCES
        "src/*.cpp"
        "include/*.cpp"
)
file(GLOB_RECURSE HEADERS
        "include/*.h"
        "include/*.hpp"
        "src/*.h"
)

add_executable(CPlusPlusClient ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(CPlusPlusClient PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(ARGON2_INCLUDE_DIR)
    target_include_directories(CPlusPlusClient PRIVATE ${ARGON2_INCLUDE_DIR})
endif()

# Link libraries
target_link_libraries(CPlusPlusClient PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        SQLite::SQLite3
)

if(TARGET PkgConfig::ARGON2)
    target_link_libraries(CPlusPlusClient PRIVATE PkgConfig::ARGON2)
elseif(ARGON2_LIBRARY)
    target_link_libraries(CPlusPlusClient PRIVATE ${ARGON2_LIBRARY})
endif()

# Platform-specific deployment (Windows only)
if(WIN32)
    # Get Qt installation path from the target
    get_target_property(QT_LIB_LOCATION Qt6::Core LOCATION)
    get_filename_component(QT_INSTALL_BIN "${QT_LIB_LOCATION}" DIRECTORY)
    get_filename_component(QT_INSTALL_ROOT "${QT_INSTALL_BIN}/.." ABSOLUTE)

    set(DEBUG_SUFFIX "")
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif()

    # 1. Create platforms directory
    add_custom_command(TARGET CPlusPlusClient POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:CPlusPlusClient>/plugins/platforms/"
    )

    # 2. Copy platform plugin (qwindows.dll)
    set(QT_PLATFORM_PLUGIN "${QT_INSTALL_ROOT}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
    if(EXISTS "${QT_PLATFORM_PLUGIN}")
        add_custom_command(TARGET CPlusPlusClient POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_PLATFORM_PLUGIN}"
                "$<TARGET_FILE_DIR:CPlusPlusClient>/plugins/platforms/"
        )
    else()
        message(WARNING "Qt platform plugin not found at: ${QT_PLATFORM_PLUGIN}")
    endif()

    # 3. Copy core Qt DLLs
    foreach(QT_LIB Core Gui Widgets)
        set(QT_DLL "${QT_INSTALL_BIN}/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll")
        if(EXISTS "${QT_DLL}")
            add_custom_command(TARGET CPlusPlusClient POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy
                    "${QT_DLL}"
                    "$<TARGET_FILE_DIR:CPlusPlusClient>"
            )
        else()
            message(WARNING "Qt DLL not found: ${QT_DLL}")
        endif()
    endforeach()
endif()