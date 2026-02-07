cmake_minimum_required(VERSION 3.21.0)
project(lazy_import VERSION 0.1.0 LANGUAGES CXX)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_23)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-exceptions)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-unwind-tables)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-rtti)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} INTERFACE /D_HAS_EXCEPTIONS=0)
    target_compile_options(${PROJECT_NAME} INTERFACE /utf-8)
endif()

add_library(witch_cult::lazy_import ALIAS ${PROJECT_NAME})

if (PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

enable_testing()
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()


include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS lazy_import
    EXPORT lazy_importTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(
    EXPORT lazy_importTargets
    FILE lazy_importTargets.cmake
    NAMESPACE witch_cult::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lazy_import
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

configure_package_config_file(
    "cmake/lazy_importConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/lazy_importConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lazy_import"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/lazy_importConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/lazy_importConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/lazy_importConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lazy_import
)
