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

if(NOT DEFINED Qt6_DIR)
    set(Qt6_DIR "" CACHE PATH "Path to Qt6 CMake directory")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add source files
set(SOURCES
    main.cpp
    UI.cpp
    model.cpp
)

# Add header files
set(HEADERS
    include/FileManager.hpp
    include/User.hpp
        include/nlohmann/json.hpp
    include/FileEncryption.hpp
        utils/pac.h
        utils/pac.cpp
        utils/CryptoUtils.h
        utils/CryptoUtils.cpp
)

add_executable(untitled5 ${SOURCES} ${HEADERS})

target_link_libraries(untitled5 
    Qt::Core 
    Qt::Gui 
    Qt::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
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
