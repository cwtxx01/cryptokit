cmake_minimum_required(VERSION 3.28)

project(cryptokit 
    VERSION 0.0.1
    LANGUAGES C CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(CRYPTOKIT_TEST "Build unit tests" ON)
option(CRYPTOKIT_SHARED "Build shared libraries" OFF)
option(CRYPTOKIT_INSTALL "Install cryptokit library" ON)

if(CRYPTOKIT_SHARED)
    add_library(cryptokit SHARED)
    set_target_properties(cryptokit PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
else() 
    add_library(cryptokit STATIC)
endif()


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


if(CRYPTOKIT_TEST)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(
        GTest
        URL https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz
        URL_HASH SHA256=6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5
        EXCLUDE_FROM_ALL
        SYSTEM
        FIND_PACKAGE_ARGS
    )
    FetchContent_MakeAvailable(GTest)

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

if(CRYPTOKIT_INSTALL)
    include(GNUInstallDirs)

    install(TARGETS cryptokit 
        EXPORT cryptokitTarget
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} 
    )

    install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/" 
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(EXPORT cryptokitTarget
        FILE cryptokitTarget.cmake
        NAMESPACE cryptokit::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptokit
    )

    include(CMakePackageConfigHelpers)

    configure_package_config_file(
        "${PROJECT_SOURCE_DIR}/cmake/cryptokitConfig.cmake.in"
        "${PROJECT_BINARY_DIR}/cryptokitConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cryptokit"
    )

    write_basic_package_version_file(
        "${PROJECT_BINARY_DIR}/cryptokitConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        "${PROJECT_BINARY_DIR}/cryptokitConfig.cmake"
        "${PROJECT_BINARY_DIR}/cryptokitConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cryptokit"
    )

endif()
