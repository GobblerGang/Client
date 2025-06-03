cmake_minimum_required(VERSION 3.27)
project(CPlusPlusClient)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/local_config.cmake")
endif()

if(NOT DEFINED CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "" CACHE PATH "Additional CMake search path")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Add compiler flags to suppress specific warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
    # Add flags for Clang/GCC
    add_compile_options(
        -Wno-deprecated-declarations   # Suppress warnings about deprecated C++17 features
        -Wno-c++20-extensions          # Suppress warnings about C++20 extensions
        -Wno-c++26-extensions          # Suppress warnings about C++26 extensions
    )
elseif(MSVC)
    # Add flags for MSVC
    add_compile_options(
        /wd4996  # Suppress warnings about deprecated functions
    )
endif()

if(NOT DEFINED Qt6_DIR)
    set(Qt6_DIR "" CACHE PATH "Path to Qt6 CMake directory")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

find_package(SQLite3 REQUIRED)

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add source files
set(SOURCES
    main.cpp
    UI.cpp
        include/utils/CryptoUtils.cpp
)

# Add header files
set(HEADERS
        include/nlohmann/json.hpp
        include/sqlite_orm/sqlite_orm.h
        include/utils/dataclasses/PAC.h
        include/utils/dataclasses/PAC.cpp
        include/utils/CryptoUtils.h
        include/utils/CryptoUtils.cpp
        include/utils/MasterKey.h
        include/utils/MasterKey.cpp
        include/utils/VaultManager.h
        include/utils/VaultManager.cpp
        include/utils/Ed25519Key.h
        include/utils/Ed25519Key.cpp
        include/utils/X25519Key.h
        include/utils/X25519Key.cpp
        include/database/models.h
        include/database/schema.hpp
        include/database/db_instance.h
        src/auth.h
        src/auth.cpp
        include/utils/dataclasses/Vault.h
        include/utils/dataclasses/Vault.cpp

)

add_executable(CPlusPlusClient ${SOURCES} ${HEADERS})
target_link_libraries(CPlusPlusClient
    Qt::Core 
    Qt::Gui 
    Qt::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
        ${ARGON2_LIB}
        ${SQLite3_LIBRARIES}
)
if (WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(DEBUG_SUFFIX "")
    if (MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif ()

    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif ()
    endif ()

    if (EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
    endif ()

    foreach (QT_LIB Core Gui Widgets)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach ()
endif ()