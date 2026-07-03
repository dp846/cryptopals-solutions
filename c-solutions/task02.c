// Fixed XOR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"

int main(void) {
    printf("Task 2: Fixed XOR with hex conversions \n");

    int ret = CRYPTOPALS_SUCCESS;

    const char* hex_str = "1c0111001f010100061a024b53535009181c";
    const char* xor_with = "686974207468652062756c6c277320657965";
    const char* expected_result = "746865206b696420646f6e277420706c6179";

    size_t bytes_length = strlen(hex_str) / 2;
    uint8_t* buffer1 = NULL;
    uint8_t* buffer2 = NULL;
    uint8_t* result_buffer = NULL;

    // Convert both hex strings to bytes
    if (strlen(hex_str) != strlen(xor_with)) {
        printf("ERROR: hex lengths are not equal. Cannot perform xor operation. \n");
        ret = CRYPTOPALS_FAIL;
        goto err_unequal_length;
    }

    // Calloc buffer1
    if ((buffer1 = calloc(bytes_length, sizeof(uint8_t))) == NULL) {
        printf("ERROR: Calloc buffer1\n");
        ret = CRYPTOPALS_FAIL;
        goto err_alloc_buffer1;
    }

    // Calloc buffer2
    if ((buffer2 = calloc(bytes_length, sizeof(uint8_t))) == NULL) {
        printf("ERROR: Calloc buffer2\n");
        ret = CRYPTOPALS_FAIL;
        goto err_alloc_buffer2;
    }

    // Calloc result buffer
    if ((result_buffer = calloc(bytes_length, sizeof(uint8_t))) == NULL) {
        printf("ERROR: Calloc result bytes\n");
        ret = CRYPTOPALS_FAIL;
        goto err_alloc_result;
    }

    // Convert buffer1 to bytes
    if (hex_to_bytes(hex_str, buffer1) != 0) {
        printf("ERROR: hex conversion buffer1\n");
        ret = CRYPTOPALS_FAIL;
        goto err_convert_buffer1;
    }

    // Convert buffer2 to bytes
    if (hex_to_bytes(xor_with, buffer2) != 0) {
        printf("ERROR: hex conversion buffer2\n");
        ret = CRYPTOPALS_FAIL;
        goto err_convert_buffer2;
    }

    // Perform xor on buffers
    printf("\nXORing  %s  with  %s ", hex_str, xor_with);
    if (xor_on_bytes(buffer1, buffer2, result_buffer, bytes_length) != 0) {
        printf("ERROR: XOR failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_xor;
    }

    printf("\n\nHex result: ");
    for (size_t i = 0; i < bytes_length; i++) {
        printf("%x", result_buffer[i]);
    }

    printf("\n\nHex expected: %s", expected_result);

    printf("\n\nDecoding the result gives: ");
    for (size_t i = 0; i < bytes_length; i++) {
        printf("%c", result_buffer[i]);
    }

    printf("\n\n");

err_xor:
err_convert_buffer2:
err_convert_buffer1:
    free(result_buffer);
err_alloc_result:
    free(buffer2);
err_alloc_buffer2:
    free(buffer1);
err_alloc_buffer1:
err_unequal_length:
    return ret;
}
