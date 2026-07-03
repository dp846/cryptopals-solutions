// Implement repeating-key XOR

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"
#include "zero_memory.h"

int main(void) {
    printf("Task 5: Implement repeating-key XOR \n");

    int ret = CRYPTOPALS_SUCCESS;

    // Init values
    const uint8_t plaintext[] = {'B', 'u', 'r', 'n', 'i',  'n', 'g', ' ', '\'', 'e', 'm', ',', ' ', 'i', 'f', ' ', 'y', 'o', 'u',
                                 ' ', 'a', 'i', 'n', '\'', 't', ' ', 'q', 'u',  'i', 'c', 'k', ' ', 'a', 'n', 'd', ' ', 'n', 'i',
                                 'm', 'b', 'l', 'e', '\n', 'I', ' ', 'g', 'o',  ' ', 'c', 'r', 'a', 'z', 'y', ' ', 'w', 'h', 'e',
                                 'n', ' ', 'I', ' ', 'h',  'e', 'a', 'r', ' ',  'a', ' ', 'c', 'y', 'm', 'b', 'a', 'l'};
    uint8_t key[] = {'I', 'C', 'E'};
    const size_t pt_len = 74;
    const size_t key_len = 3;

    // Initilase a buffer for the result
    uint8_t* result_buffer = NULL;

    // Extend the key
    uint8_t* key_extended = extend_key_repeated(key, key_len, pt_len);
    if (!key_extended) {
        printf("Error extending the key.\n");
        ret = CRYPTOPALS_FAIL;
        goto err_malloc_extkey;
    }

    // Malloc a result buffer
    result_buffer = calloc(pt_len, sizeof(uint8_t));
    if (!result_buffer) {
        printf("ERROR: malloc result bytes\n");
        ret = CRYPTOPALS_FAIL;
        goto err_malloc_result;
    }

    // Now perform xor on the extended key and the plaintext bytes
    if (xor_on_bytes(plaintext, key_extended, result_buffer, pt_len) != 0) {
        printf("ERROR: XOR failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_xor;
    }

    // Output
    printf("\n\nDecoding the result gives: ");
    for (size_t i = 0; i < pt_len; i++) {
        printf("%02x", result_buffer[i]);
    }
    printf("\n");

err_xor:
    free(result_buffer);
err_malloc_result:

// Zero out the extended key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(key_extended, pt_len);
#else
    zero_memory(key_extended, pt_len, pt_len);
    free(key_extended);
#endif

err_malloc_extkey:

// Zero out the key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(key, key_len);
#else
    zero_memory(key, key_len, key_len);
#endif

    return ret;
}
