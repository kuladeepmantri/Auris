cmake_minimum_required(VERSION 3.16)
project(sysguard VERSION 1.0.0 LANGUAGES C)

# Require C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Build options
option(BUILD_STATIC "Build static executable" OFF)
option(BUILD_TESTS "Build test suite" ON)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-truncation -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0 -DDEBUG")

# Release flags
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -DNDEBUG")

# Sanitizer support
if(ENABLE_SANITIZERS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JSONC REQUIRED json-c)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSONC_INCLUDE_DIRS}
)

# Source files
set(SYSGUARD_SOURCES
    src/main.c
    src/tracer.c
    src/syscall_table.c
    src/trace_store.c
    src/json_utils.c
    src/profiler.c
    src/dataflow.c
    src/graph.c
    src/policy.c
    src/enforcer.c
    src/ai_client.c
    src/cli.c
    src/utils.c
    src/logging.c
    src/arm_regs.c
    src/sensitive_paths.c
    src/pattern_match.c
)

# Create the main executable
add_executable(sysguard ${SYSGUARD_SOURCES})

# Link libraries
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    target_link_libraries(sysguard
        ${CURL_STATIC_LIBRARIES}
        ${JSONC_STATIC_LIBRARIES}
        pthread
        dl
    )
else()
    target_link_libraries(sysguard
        ${CURL_LIBRARIES}
        ${JSONC_LIBRARIES}
        OpenSSL::Crypto
        pthread
        m
    )
endif()

target_link_directories(sysguard PRIVATE
    ${CURL_LIBRARY_DIRS}
    ${JSONC_LIBRARY_DIRS}
)

# PIE for ASLR
set_target_properties(sysguard PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    LINK_FLAGS "-pie"
)

# Install target
install(TARGETS sysguard DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/sysguard)

# Testing
if(BUILD_TESTS)
    enable_testing()
    pkg_check_modules(CHECK REQUIRED check)
    
    # Test sources
    set(TEST_SOURCES
        tests/test_main.c
        tests/test_syscall_table.c
        tests/test_trace_store.c
        tests/test_profiler.c
        tests/test_dataflow.c
        tests/test_graph.c
        tests/test_policy.c
        tests/test_json_utils.c
        tests/test_pattern_match.c
        tests/test_arm_regs.c
        # Include necessary source files for testing
        src/syscall_table.c
        src/trace_store.c
        src/json_utils.c
        src/profiler.c
        src/dataflow.c
        src/graph.c
        src/policy.c
        src/utils.c
        src/logging.c
        src/arm_regs.c
        src/sensitive_paths.c
        src/pattern_match.c
    )
    
    add_executable(sysguard_tests ${TEST_SOURCES})
    
    target_include_directories(sysguard_tests PRIVATE
        ${CHECK_INCLUDE_DIRS}
    )
    
    target_link_libraries(sysguard_tests
        ${CHECK_LIBRARIES}
        ${JSONC_LIBRARIES}
        ${CURL_LIBRARIES}
        pthread
        m
    )
    
    target_link_directories(sysguard_tests PRIVATE
        ${CHECK_LIBRARY_DIRS}
        ${JSONC_LIBRARY_DIRS}
        ${CURL_LIBRARY_DIRS}
    )
    
    add_test(NAME unit_tests COMMAND sysguard_tests)
    
    # Integration tests
    add_test(NAME integration_trace_simple
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration/test_trace_simple.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    
    add_test(NAME integration_policy_enforce
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration/test_policy_enforce.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    
    add_test(NAME integration_profile_compare
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration/test_profile_compare.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endif()

# Documentation
find_program(DOXYGEN doxygen)
if(DOXYGEN)
    add_custom_target(docs
        COMMAND ${DOXYGEN} ${CMAKE_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating documentation"
    )
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "SysGuard Configuration Summary")
message(STATUS "==============================")
message(STATUS "Version:          ${PROJECT_VERSION}")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "Static build:     ${BUILD_STATIC}")
message(STATUS "Build tests:      ${BUILD_TESTS}")
message(STATUS "Sanitizers:       ${ENABLE_SANITIZERS}")
message(STATUS "C Compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "C Flags:          ${CMAKE_C_FLAGS}")
message(STATUS "")
