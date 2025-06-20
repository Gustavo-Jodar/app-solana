include_guard()
cmake_minimum_required(VERSION 3.14)

if(${CMAKE_VERSION} VERSION_LESS 3.14)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(
  APP-SOLANAFuzzer
  VERSION 1.0
  DESCRIPTION "App solana example Fuzzer"
  LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
else()
  message(${BOLOS_SDK})
endif()

add_subdirectory(${BOLOS_SDK}/fuzzing
                 ${CMAKE_CURRENT_BINARY_DIR}/ledger-secure-sdk EXCLUDE_FROM_ALL)

file(
  GLOB
  C_SOURCES
  "${CMAKE_SOURCE_DIR}/../src/*.c"
  "${CMAKE_SOURCE_DIR}/../src/swap/*.c"
  "${CMAKE_SOURCE_DIR}/../src/tlv/*.c"
  "${CMAKE_SOURCE_DIR}/../src/ui/*.c"
  "${CMAKE_SOURCE_DIR}/../libsol/*.c"  
  "${CMAKE_SOURCE_DIR}/mock/*.c")
list(REMOVE_ITEM C_SOURCES "${CMAKE_SOURCE_DIR}/../src/main.c")

add_library(code_lib ${C_SOURCES})

target_include_directories(
  code_lib
  PUBLIC ${CMAKE_SOURCE_DIR}/../src/
         ${CMAKE_SOURCE_DIR}/../src/swap/
         ${CMAKE_SOURCE_DIR}/../src/swap/
         ${CMAKE_SOURCE_DIR}/../src/tlv/
         ${CMAKE_SOURCE_DIR}/../src/ui/
         ${CMAKE_SOURCE_DIR}/../libsol/
         ${CMAKE_SOURCE_DIR}/../libsol/include/
         ${CMAKE_SOURCE_DIR}/../libsol/include/sol/
         ${CMAKE_SOURCE_DIR}/../libsol/include/spl/
         ${CMAKE_SOURCE_DIR}/mock/
         ${CMAKE_SOURCE_DIR}/)

target_link_libraries(code_lib PUBLIC extra)
target_compile_definitions(
  code_lib PUBLIC ${DEFINES})

 # fuzz_handle_apdu
add_executable(fuzz_handle_apdu "${CMAKE_SOURCE_DIR}/harness/fuzz_handle_apdu.c")
target_compile_definitions(
  fuzz_handle_apdu PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
target_link_libraries(fuzz_handle_apdu PUBLIC extra code_lib)

# fuzz_message
add_executable(fuzz_message "${CMAKE_SOURCE_DIR}/harness/fuzz_message.c")
target_compile_definitions(
  fuzz_message PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
target_link_libraries(fuzz_message PUBLIC extra code_lib)

# fuzz_dynamic_descriptor
add_executable(fuzz_dynamic_descriptor "${CMAKE_SOURCE_DIR}/harness/fuzz_dynamic_descriptor.c")
target_compile_definitions(
  fuzz_dynamic_descriptor PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
target_link_libraries(fuzz_dynamic_descriptor PUBLIC extra code_lib)

# fuzz_handle_provide_trusted_info
add_executable(fuzz_provide_trusted_info "${CMAKE_SOURCE_DIR}/harness/fuzz_provide_trusted_info.c")
target_compile_definitions(
  fuzz_provide_trusted_info PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
target_link_libraries(fuzz_provide_trusted_info PUBLIC extra code_lib)
