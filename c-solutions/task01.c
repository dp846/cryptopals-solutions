// Convert hex to base64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "error_codes.h"

int main(void) {
    printf("Task 1: Conversions from base 64 to hex. \n\n");

    int ret = CRYPTOPALS_SUCCESS;

    // Initialise values
    const char* hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const char* b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    const size_t b64_len = strlen(b64_str);

    size_t bytes_length = strlen(hex_str) / 2;

    uint8_t* bytes_result;
    char* b64_result;

    // Allocate a buffer for the resulting bytes
    if ((bytes_result = calloc(bytes_length, sizeof(uint8_t))) == NULL) {
        printf("ERROR: malloc result bytes\n");
        ret = CRYPTOPALS_FAIL;
        goto err_alloc_result;
    }

    // Conversion to bytes
    if (hex_to_bytes(hex_str, bytes_result) != 0) {
        printf("ERROR: hex_to_bytes a\n");
        ret = CRYPTOPALS_FAIL;
        goto err_hex_bytes;
    }

    printf("Bytes from hex string:  ");
    for (size_t i = 0; i < bytes_length; i++) {
        printf("%02x ", (uint8_t)bytes_result[i]);
    }
    printf("\n");

    // Conversion from bytes to base64
    b64_result = bytes_to_base64(bytes_result, bytes_length);
    if (!b64_result) {
        ret = CRYPTOPALS_FAIL;
        goto err_bytes_base64;
    }

    // Output the resulting base64
    printf("\nBase64 from bytes:  ");
    printf("%s", b64_result);

    // Output the expected base64
    printf("\nExpected base 64 result:  ");
    printf("%s", b64_str);

    // Memory compare the result to expected
    if (memcmp(b64_result, b64_str, b64_len) == 0) {
        printf("\nPASS - The result matches the expected.");
    } else {
        printf("\nFAIL - The result does not match the expected. ");
        ret = CRYPTOPALS_FAIL;
    }
    printf("\n");

    free(b64_result);

err_bytes_base64:
err_hex_bytes:
    free(bytes_result);
err_alloc_result:
    return ret;
}
