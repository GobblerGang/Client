cmake_minimum_required(VERSION 3.27)

# Enable vcpkg toolchain on Windows if available (must be before project())
if(WIN32 AND DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
elseif(WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(WARNING "VCPKG_ROOT environment variable not set. Ensure vcpkg is integrated.")
endif()

project(CPlusPlusClient)

# Allow local configuration overrides
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
endif()

set(CMAKE_CXX_STANDARD 17)
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

# Find dependencies (all via vcpkg)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)
if(WIN32)
    find_path(ARGON2_INCLUDE_DIR argon2.h)
    find_library(ARGON2_LIBRARY argon2)
    if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
        message(FATAL_ERROR "Argon2 not found")
    endif()
endif()

# Source and header files
set(SOURCES
        main.cpp
        UI.cpp
        src/auth.cpp
        include/utils/CryptoUtils.cpp
        include/utils/MasterKey.cpp
        include/utils/VaultManager.cpp
        include/utils/Ed25519Key.cpp
        include/utils/X25519Key.cpp
        include/utils/dataclasses/PAC.cpp
        include/utils/dataclasses/Vault.cpp
        src/DataManager.cpp
)

set(HEADERS
        include/nlohmann/json.hpp
        include/sqlite_orm/sqlite_orm.h
        include/utils/dataclasses/PAC.h
        include/utils/CryptoUtils.h
        include/utils/MasterKey.h
        include/utils/VaultManager.h
        include/utils/Ed25519Key.h
        include/utils/X25519Key.h
        include/database/models.h
        include/database/schema.hpp
        include/database/db_instance.h
        src/auth.h
        include/utils/dataclasses/Vault.h
        src/DataManager.h
)

add_executable(CPlusPlusClient ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(CPlusPlusClient PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(CPlusPlusClient
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        SQLite::SQLite3
)

if(WIN32)
    target_include_directories(CPlusPlusClient PRIVATE ${ARGON2_INCLUDE_DIR})
    target_link_libraries(CPlusPlusClient ${ARGON2_LIBRARY})
endif()

# Platform-specific deployment (Windows)
if(WIN32)
    get_target_property(QT_LIB_LOCATION Qt6::Core LOCATION)
    get_filename_component(QT_INSTALL_BIN "${QT_LIB_LOCATION}" DIRECTORY)
    get_filename_component(QT_INSTALL_ROOT "${QT_INSTALL_BIN}/.." ABSOLUTE)

    set(DEBUG_SUFFIX "")
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif()

    add_custom_command(TARGET CPlusPlusClient POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:CPlusPlusClient>/plugins/platforms/"
    )

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