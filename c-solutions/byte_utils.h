#ifndef BYTE_UTILS
#define BYTE_UTILS

#include <stddef.h>
#include <stdint.h>

/**
 * Outputs bytes in hex fomatting
 *
 * @param bytes pointer to array of bytes to print
 * @param len length of bytes array to print
 */
void print_bytes(const uint8_t* bytes, size_t len);

/**
 * Converts a string of hex to an array of bytes
 * @param hex char pointer to a string of hex to convert
 * @param bytes uint8_t point to an array of bytes
 *
 * @returns 0 if success, non-zero error code for failure
 */
int hex_to_bytes(const char* hex, uint8_t* bytes);

/**
 * Converts array of bytes to a string of base 64
 *
 * @param bytes pointer to an array of bytes
 * @param bytes_length length of the bytes to convert
 *
 * @returns string of the base 64 result
 */
char* bytes_to_base64(const uint8_t* bytes, size_t bytes_length);

/**
 * Decodes a single given base 64 character
 *
 * @param c uint8_t of the char to decode in the base64 character list
 *
 * @returns -1 for invalid character, or the value index that corresponds to the base64 character on success (>= 0)
 */
int decode_b64_char(uint8_t c);

/**
 * Converts a given stream of base64 data to a buffer of bytes
 *
 * @param b64 array of b64
 * @param len size_t length of the b64 array
 * @param output_buffer pointer to an array for the resulting bytes
 * @param output_len pointer to the length of the output bytes array after the operation
 *
 * @returns 0 on success, non-zero error code for failure
 */
int base64_to_bytes(const uint8_t* b64, size_t len, uint8_t** output_buffer, size_t* output_len);

#endif
