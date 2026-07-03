cmake_minimum_required(VERSION 3.20)
project(cryptopals VERSION 1)
enable_language(C)

# ----------------------------------------- #
# ---------------- LIBRARIES -------------- #
# ----------------------------------------- #

# CLI option for using libsodium
option(USE_LIBSODIUM "Link against libsodium" OFF)

# Create a static library for byte utils
add_library(byte_utils)
target_sources(byte_utils PRIVATE byte_utils.c)
target_compile_options(byte_utils PRIVATE -Wall -Wextra -Wpedantic)
# Create a static library for crypto utils
add_library(crypto_utils)
target_sources(crypto_utils PRIVATE crypto_utils.c)
target_compile_options(crypto_utils PRIVATE -Wall -Wextra -Wpedantic)

# Find and link OpenSSL to crypto_utils library
find_package(OpenSSL REQUIRED)
target_link_libraries(crypto_utils PRIVATE OpenSSL::Crypto)

# Create a static library for file utils
add_library(file_utils)
target_sources(file_utils PRIVATE file_utils.c)
target_compile_options(file_utils PRIVATE -Wall -Wextra -Wpedantic)

# ----------------------------------------- #
# --------- CHALLENGE EXECUTABLES --------- #
# ----------------------------------------- #

# Function to create an executable
function(create_crypto_task TASK_NUMBER SOURCE_FILE)
    set(TARGET_NAME "crypto_task${TASK_NUMBER}")
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -Wpedantic)

    # Link all common util libraries
    target_link_libraries(${TARGET_NAME} PRIVATE byte_utils crypto_utils file_utils)

    # Linking libsodium
    if(USE_LIBSODIUM)
        target_compile_definitions(${TARGET_NAME} PRIVATE USE_LIBSODIUM)
        target_link_libraries(${TARGET_NAME} PRIVATE sodium)
    endif()
endfunction()

# Use the function to create each executable
set(TASK_NUMBERS 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16)
foreach(TASK_NUM ${TASK_NUMBERS})
  create_crypto_task(${TASK_NUM} "task${TASK_NUM}.c")
endforeach()