if (NOT BUILD_TESTING)
    return()
endif()

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.8.0
)
FetchContent_MakeAvailable(Catch2)
target_compile_features(Catch2 PRIVATE cxx_std_17)
target_compile_features(Catch2WithMain PRIVATE cxx_std_17)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)

add_executable(lazy_import_tests test.cpp)

target_link_libraries(lazy_import_tests
    PRIVATE
        witch_cult::lazy_import
        Catch2::Catch2WithMain
)
target_compile_features(lazy_import_tests PRIVATE cxx_std_23)

catch_discover_tests(lazy_import_tests)
