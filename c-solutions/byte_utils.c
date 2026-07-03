#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "error_codes.h"

#define MAX_BUFFER_SIZE 4096

void print_bytes(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int hex_to_bytes(const char* hex, uint8_t* bytes) {

    if (!hex || !bytes) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    const size_t hex_length = strlen(hex);

    // Check for odd length of hex
    if (hex_length % 2 != 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    char hex_pair[3]; // Two hex chars plus null terminator

    for (size_t i = 0, j = 0; i < hex_length && i <= (SIZE_MAX - 2); i += 2, j++) {

        hex_pair[0] = hex[i];
        hex_pair[1] = hex[i + 1];
        hex_pair[2] = '\0';

        // Convert the pair
        char* endptr;
        errno = 0;
        unsigned long byte_val = strtoul(hex_pair, &endptr, 16);

        // Check for strtoul errors
        if (errno == ERANGE && byte_val == ULONG_MAX) { // Check errno
            printf("ERROR: Strtoul out of range\n");
            return CRYPTOPALS_ERR_OUTOFBOUNDS;
        } else if (endptr == hex_pair) { // Check for failure to convert hex pair to byte
            printf("ERROR: No conversion took place\n");
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        } else {

            // Check that the byte value is 255 or less before assignment
            if (byte_val > UINT8_MAX) {
                printf("ERROR: Invalid byte value\n");
                return CRYPTOPALS_ERR_MISCELLANEOUS;
            }
            bytes[j] = (uint8_t)byte_val;
        }
    }

    return CRYPTOPALS_SUCCESS;
}

char* bytes_to_base64(const uint8_t* bytes, size_t bytes_length) {

    const char BASE64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Check if bytes_length wrapping will occur (i += 3 in the loop)
    if (bytes_length > (SIZE_MAX - 4)) {
        printf("ERROR: Wrapping occured\n");
        return NULL;
    }

    size_t base64_length = ((bytes_length + 2) / 3) * 4; // Allocate the bytes required

    if (base64_length + 1 > MAX_BUFFER_SIZE) { // Check for array exceeding my max buffer size
        printf("ERROR: Buffer size exceeded\n");
        return NULL;
    }

    // Malloc for b64 and check if successful
    char* base64 = (char*)malloc(base64_length + 1); // Account for terminator
    if (!base64) {
        printf("ERROR: Malloc failure\n");
        return NULL;
    }

    size_t b64_index = 0;

    // Group into 3 bytes
    for (size_t i = 0; i < bytes_length; i += 3) {

        // Look at values for first 3 bytes - check for overruns before assigning bytes 2 and 3
        uint8_t byte1 = bytes[i];
        uint8_t byte2 = 0;
        uint8_t byte3 = 0;
        if ((i + 1) < bytes_length) {
            byte2 = bytes[i + 1];
        }
        if ((i + 2) < bytes_length) {
            byte3 = bytes[i + 2];
        }

        // index1 uses the first 6 bits from byte1
        uint8_t first6BitsOfByte1 = byte1 >> 2;
        size_t index1 = first6BitsOfByte1;

        // index2, combine the last 2 bits of byte1 and the first 4 bits of byte2
        uint8_t last2BitsOfByte1 = byte1 & 0x3;
        uint8_t first4BitsOfByte2 = byte2 >> 4;
        size_t index2 = (last2BitsOfByte1 << 4) | first4BitsOfByte2;

        // index3, combine the last 4 bits of byte2 and the first 2 bits of byte3
        uint8_t last4BitsOfByte2 = byte2 & 0xF;
        uint8_t first2BitsOfByte3 = byte3 >> 6;
        size_t index3 = (last4BitsOfByte2 << 2) | first2BitsOfByte3;

        // index 4, use the last 6 bits from byte3
        size_t index4 = byte3 & 0x3F;

        const char padchr = '=';

        // Check for overrun before array access
        if (b64_index + 4 > base64_length) {
            printf("ERROR: Buffer overrun detected\n");
            free(base64);
            return NULL;
        }

        // Map each index to a b64 char and add it onto the ongoing base64 string
        base64[b64_index++] = BASE64_ALPHABET[index1];
        base64[b64_index++] = BASE64_ALPHABET[index2];
        base64[b64_index++] = (i + 1 < bytes_length) ? BASE64_ALPHABET[index3] : padchr;
        base64[b64_index++] = (i + 2 < bytes_length) ? BASE64_ALPHABET[index4] : padchr;
    }

    // Null terminate the string and return
    base64[b64_index] = '\0';
    return base64;
}

int decode_b64_char(uint8_t chr) {

    const char B64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Check for non ASCII char (can't be b64 char then)
    if (chr >= 128) {
        return CRYPTOPALS_FAIL_N;
    }

    // Look for the position of the char in the alphabet
    const char* position = strchr(B64_ALPHABET, chr);
    if (position) {
        ptrdiff_t diff = position - B64_ALPHABET;

        if (diff > INT_MAX || diff < INT_MIN) {
            printf("ERROR: Data would be lost casting to int\n");
            return CRYPTOPALS_FAIL_N;
        }

        return (int)diff;
    }
    return CRYPTOPALS_FAIL_N;
}

int base64_to_bytes(const uint8_t* b64, size_t len, uint8_t** output_buffer, size_t* output_len) {

    // Check for incorrect lengths
    if (len % 4 != 0 || len < 4) {
        printf("ERROR: Invalid base64 length");
        return CRYPTOPALS_ERR_LENGTH;
    }

    size_t temp_len = (len / 4) * 3;

    // Adjust output bytes length for padding
    if (b64[len - 1] == '=' && temp_len > 0) {
        temp_len--;
    }
    if (b64[len - 2] == '=' && temp_len > 0) {
        temp_len--;
    }

    // Malloc the buffer for bytes
    uint8_t* buffer = (uint8_t*)malloc(temp_len);
    if (!buffer) {
        printf("ERROR: Malloc failed for buffer");
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    size_t bytes_index = 0;
    for (size_t i = 0; i < len; i += 4) { // Base64 indexer

        // For valid b64, = could be in the last 2 positions
        // decode_b64_char does not have an = check in it (would complain about it being invalid), so we check in this function

        int val0 = decode_b64_char(b64[i]);
        int val1 = decode_b64_char(b64[i + 1]);

        if (val0 == -1 || val1 == -1) { // Check for incorrect b64 values
            printf("ERROR: Invalid b64 character encountered\n");
            free(buffer);
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }

        buffer[bytes_index++] = (val0 << 2) | (val1 >> 4);

        if (b64[i + 2] != '=') {
            int val2 = decode_b64_char(b64[i + 2]);

            if (val2 == -1) { // Check for incorrect b64 value
                printf("ERROR: Invalid b64 character encountered\n");
                free(buffer);
                return CRYPTOPALS_ERR_MISCELLANEOUS;
            }

            buffer[bytes_index++] = (val1 << 4) | (val2 >> 2);
        }
        if (b64[i + 3] != '=') {
            int val2 = decode_b64_char(b64[i + 2]);
            int val3 = decode_b64_char(b64[i + 3]);

            if (val3 == -1) { // Check for incorrect b64 value
                printf("ERROR: Invalid b64 character encountered\n");
                free(buffer);
                return CRYPTOPALS_ERR_MISCELLANEOUS;
            }

            buffer[bytes_index++] = (val2 << 6) | val3;
        }
    }

    // Set values and return success
    *output_buffer = buffer;
    *output_len = temp_len;
    return CRYPTOPALS_SUCCESS;
}
