// Single-byte XOR cipher

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"

int main(void) {
    printf("Task 3: Single bytes XOR cipher \n");

    int ret = CRYPTOPALS_SUCCESS;

    const char* ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    size_t ct_len = strlen(ciphertext_hex) / 2;
    uint8_t* ct_buffer;

    // Calloc buffer1
    if ((ct_buffer = calloc(ct_len, sizeof(uint8_t))) == NULL) {
        printf("ERROR: Calloc buffer1\n");
        ret = CRYPTOPALS_FAIL;
        goto err_malloc_buffer;
    }

    // convert from hex to bytes
    if (hex_to_bytes(ciphertext_hex, ct_buffer) != 0) {
        printf("ERROR: Hex conversion buffer\n");
        ret = CRYPTOPALS_FAIL;
        goto err_convert_buffer;
    }

    // Call single byte xor decrypt
    uint8_t* best_plaintext;
    uint8_t key_byte;

    if ((best_plaintext = single_byte_xor_decryption(ct_buffer, ct_len, &key_byte)) != NULL) {
        printf("\nDecrypted message: %s\n", best_plaintext);
        free(best_plaintext);
    } else {
        printf("ERROR: Null pointer to result\n");
        goto err_malloc_result;
    }

    printf("\n\n");

err_malloc_result:
err_convert_buffer:
    free(ct_buffer);
err_malloc_buffer:
    return ret;
}
