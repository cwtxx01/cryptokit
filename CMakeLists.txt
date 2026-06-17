cmake_minimum_required(VERSION 3.20)

project(cryptokit LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(BUILD_UNIT_TESTS "Build unit tests" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

add_library(cryptokit)

file(GLOB_RECURSE src_files CONFIGURE_DEPENDS
    ${PROJECT_SOURCE_DIR}/src/*.cpp
)

target_sources(cryptokit PRIVATE
    ${src_files}
)

target_include_directories(cryptokit PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(cryptokit PRIVATE cxx_std_17)

target_compile_options(cryptokit PRIVATE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wall>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wextra>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wshadow>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wunused>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wundef>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wpedantic> 
)

find_package(OpenSSL REQUIRED)

target_link_libraries(cryptokit PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL
)

if(BUILD_SHARED_LIBS)
    set_target_properties(cryptokit PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()


if(BUILD_UNIT_TESTS)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)

    add_executable(cryptokit_ut)

    file(GLOB_RECURSE test_files CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/tests/*.cpp
    )

    target_sources(cryptokit_ut PRIVATE ${test_files})

    target_link_libraries(cryptokit_ut PRIVATE
        cryptokit
        GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(cryptokit_ut)
endif()

