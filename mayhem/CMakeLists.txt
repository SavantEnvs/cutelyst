# Mayhem fuzz build: upstream Cutelyst as a subproject (static libraries, sanitized by the
# flags build.sh passes in), plus one libFuzzer binary and one standalone reproducer per harness.
cmake_minimum_required(VERSION 3.28)
project(cutelyst_fuzz LANGUAGES C CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. cutelyst)

find_package(Qt6 6.5 COMPONENTS Core Network REQUIRED)

set(FUZZ_ENGINE_FLAGS "" CACHE STRING "Link flags of the fuzzing engine (LIB_FUZZING_ENGINE)")
set(STANDALONE_MAIN "" CACHE FILEPATH "Run-once driver (STANDALONE_FUZZ_MAIN)")
separate_arguments(_engine NATIVE_COMMAND "${FUZZ_ENGINE_FLAGS}")

set(LSAN_OFF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/lsan_off.cc" CACHE FILEPATH
    "TU defining __lsan_is_turned_off() (leak detection off; ASan/UBSan stay on)")
add_library(fuzz_lsan_off OBJECT ${LSAN_OFF_SRC})
add_library(fuzz_standalone_main OBJECT ${STANDALONE_MAIN})
set_source_files_properties(${STANDALONE_MAIN} PROPERTIES LANGUAGE C)

function(cutelyst_fuzzer name)
    cmake_parse_arguments(F "" "" "SOURCES;LIBS;DEFS" ${ARGN})
    foreach(kind fuzz standalone)
        if(kind STREQUAL "fuzz")
            set(tgt ${name})
        else()
            set(tgt ${name}-standalone)
        endif()
        add_executable(${tgt} ${F_SOURCES} $<TARGET_OBJECTS:fuzz_lsan_off>)
        target_include_directories(${tgt} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR}/cutelyst
            ${CMAKE_CURRENT_SOURCE_DIR}/harnesses)
        target_compile_definitions(${tgt} PRIVATE QT_NO_KEYWORDS ${F_DEFS})
        target_link_libraries(${tgt} PRIVATE Cutelyst::Core Qt::Core Qt::Network ${F_LIBS})
        if(kind STREQUAL "fuzz")
            target_link_options(${tgt} PRIVATE ${_engine})
        else()
            target_sources(${tgt} PRIVATE $<TARGET_OBJECTS:fuzz_standalone_main>)
        endif()
    endforeach()
endfunction()

set(H ${CMAKE_CURRENT_SOURCE_DIR}/harnesses)
cutelyst_fuzzer(fuzz_server_http SOURCES ${H}/fuzz_server.cpp LIBS Cutelyst::Server DEFS FUZZ_PROTO=1)
cutelyst_fuzzer(fuzz_server_http2 SOURCES ${H}/fuzz_server.cpp LIBS Cutelyst::Server DEFS FUZZ_PROTO=2)
cutelyst_fuzzer(fuzz_server_fastcgi SOURCES ${H}/fuzz_server.cpp LIBS Cutelyst::Server DEFS FUZZ_PROTO=3)
cutelyst_fuzzer(fuzz_server_websocket SOURCES ${H}/fuzz_server.cpp LIBS Cutelyst::Server DEFS FUZZ_PROTO=4)
cutelyst_fuzzer(fuzz_request SOURCES ${H}/fuzz_request.cpp ${H}/fuzz_app.h)
cutelyst_fuzzer(fuzz_staticsimple SOURCES ${H}/fuzz_staticsimple.cpp LIBS Cutelyst::StaticSimple)
cutelyst_fuzzer(fuzz_multipart SOURCES ${H}/fuzz_multipart.cpp)
cutelyst_fuzzer(fuzz_headers SOURCES ${H}/fuzz_headers.cpp)
cutelyst_fuzzer(fuzz_utils SOURCES ${H}/fuzz_utils.cpp)
cutelyst_fuzzer(fuzz_validator SOURCES ${H}/fuzz_validator.cpp LIBS Cutelyst::Utils::Validator)
