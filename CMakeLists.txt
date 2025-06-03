cmake_minimum_required(VERSION 3.27)
project(CPlusPlusClient)

# Enable vcpkg toolchain (replace with your vcpkg path if needed)
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
elseif(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(WARNING "VCPKG_ROOT environment variable not set. Ensure vcpkg is integrated.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Compiler flags
if(MSVC)
    add_compile_options(/wd4996)  # Disable deprecation warnings
else()
    add_compile_options(-Wno-deprecated-declarations)
endif()

# Find dependencies
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Find Argon2 explicitly (modern CMake)
find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
find_library(ARGON2_LIBRARY NAMES argon2 libargon2)

if(NOT ARGON2_LIBRARY OR NOT ARGON2_INCLUDE_DIR)
    message(FATAL_ERROR "Argon2 library not found. Install with: vcpkg install argon2")
endif()

# Add executable
add_executable(CPlusPlusClient
        main.cpp
        UI.cpp
        src/Auth.cpp
        include/utils/CryptoUtils.cpp
        include/utils/MasterKey.cpp
        include/utils/VaultManager.cpp
        include/utils/Ed25519Key.cpp
        include/utils/X25519Key.cpp
        include/utils/dataclasses/PAC.cpp
        include/utils/dataclasses/Vault.cpp
)

# Include directories
target_include_directories(CPlusPlusClient PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${ARGON2_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(CPlusPlusClient
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        OpenSSL::SSL
        OpenSSL::Crypto
        ${ARGON2_LIBRARY}  # Directly link the found Argon2 library
        SQLite::SQLite3
)

if(WIN32)
    # Get Qt installation path from the target (now correctly points to MSVC dir)
    get_target_property(QT_LIB_LOCATION Qt6::Core LOCATION)
    get_filename_component(QT_INSTALL_BIN "${QT_LIB_LOCATION}" DIRECTORY)
    get_filename_component(QT_INSTALL_ROOT "${QT_INSTALL_BIN}/.." ABSOLUTE)  # Goes up to msvc2022_64

    # Debug suffix
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