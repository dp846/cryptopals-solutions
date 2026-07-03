// PKCS#7 padding validation

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"

#define BLOCK_SIZE 16
#define VALID_PADDING 4
#define INVALID_PADDING 5

int main(void) {
    printf("Task 15: PKCS#7 padding validation \n");

    // --- TEST CASE 1 --- //

    // Init variables for test
    uint8_t padded_pt1[] = {'I', 'C', 'E', ' ', 'I',           'C',           'E',           ' ',
                            'B', 'A', 'B', 'Y', VALID_PADDING, VALID_PADDING, VALID_PADDING, VALID_PADDING}; // Valid padding
    size_t padded_pt_len1 = BLOCK_SIZE;
    uint8_t* stripped_pt1 = NULL;
    size_t stripped_pt_len1 = 0;

    printf("Padded plaintext: ");
    print_bytes(padded_pt1, padded_pt_len1); // Padded plaintext (valid)

    // Check the padding and strip if okay, otherwise return error code and output
    if (check_and_strip_padding(padded_pt1, padded_pt_len1, &stripped_pt1, &stripped_pt_len1) != 0) {
        printf("ERROR: Could not strip padding\n");
        return CRYPTOPALS_FAIL;
    }
    printf("Stripped plaintext: ");
    print_bytes(stripped_pt1, stripped_pt_len1); // Stripped plaintext
    printf("PASS: Plaintext had valid padding removed\n");

    free(stripped_pt1);

    // --- TEST CASE 2 --- //

    // Init variables for test
    uint8_t padded_pt2[] = {'I', 'C', 'E', ' ', 'I', 'C', 'E', ' ', 'B', 'A', 'B', 'Y', 1, 2, 3, 4}; // Invlalid padding format
    size_t padded_pt_len2 = BLOCK_SIZE;
    uint8_t* stripped_pt2 = NULL;
    size_t stripped_pt_len2 = 0;

    printf("Padded plaintext: ");
    print_bytes(padded_pt2, padded_pt_len2); // Padded plaintext (invalid)

    // Check an error code was returned, as expected
    if (check_and_strip_padding(padded_pt2, padded_pt_len2, &stripped_pt2, &stripped_pt_len2) == 0) {
        printf("FAIL: Expected an error as the padding is invalid\n");
        free(stripped_pt2);
        return CRYPTOPALS_FAIL;
    }
    printf("PASS: An error was thrown on invalid padding\n");

    // --- TEST CASE 3 --- //

    uint8_t padded_pt3[] = {'I',
                            'C',
                            'E',
                            ' ',
                            'I',
                            'C',
                            'E',
                            ' ',
                            'B',
                            'A',
                            'B',
                            'Y',
                            INVALID_PADDING,
                            INVALID_PADDING,
                            INVALID_PADDING,
                            INVALID_PADDING}; // Invalid padding format
    size_t padded_pt_len3 = 16;
    uint8_t* stripped_pt3 = NULL;
    size_t stripped_pt_len3 = 0;

    printf("Padded plaintext: ");
    print_bytes(padded_pt3, padded_pt_len3); // Padded plaintext (invalid)

    // Check an error code was returned, as expected
    if (check_and_strip_padding(padded_pt3, padded_pt_len3, &stripped_pt3, &stripped_pt_len3) == 0) {
        printf("FAIL: Expected an error as the padding is invalid\n");
        free(stripped_pt3);
        return CRYPTOPALS_FAIL;
    }

    printf("PASS: An error was thrown on invalid padding\n");

    return CRYPTOPALS_SUCCESS;
}
