# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(cxplatplatformtest.clog STATIC ${SOURCES})

add_executable(cxplatplatformtest ${SOURCES})

target_include_directories(cxplatplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET cxplatplatformtest PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(cxplatplatformtest cxplat platform inc gtest)
else()
    target_link_libraries(cxplatplatformtest cxplat platform inc gtest cxplatplatformtest.clog)
endif()

add_test(NAME cxplatplatformtest
         COMMAND cxplatplatformtest
         WORKING_DIRECTORY ${CXPLAT_OUTPUT_DIR})
