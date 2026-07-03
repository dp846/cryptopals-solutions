// Implement PKCS#7 padding

// NOTE: The BLOCK_SIZE for the padding is defined in crypto_utils - this can be changed there if need be

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"

int main(void) {
    printf("Task 9: Implement PKCS#7 padding \n");

    int ret = CRYPTOPALS_SUCCESS;

    // Test values
    uint8_t plaintext[] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B'};
    const size_t length = 10;

    uint8_t* padded_pt = NULL;
    size_t padded_pt_len = 0;

    uint8_t* stripped_pt = NULL;
    size_t stripped_pt_len = 0;

    // Apply the padding
    if (apply_pkcs7_padding(plaintext, length, &padded_pt, &padded_pt_len) != 0) {
        printf("ERROR: Padding error\n");
        ret = CRYPTOPALS_FAIL;
        goto err_apply_pad;
    }

    // Output
    printf("\nThe padded plaintext in hex is: ");
    print_bytes(padded_pt, padded_pt_len);

    // Strip padding
    if (strip_pkcs7_padding(padded_pt, padded_pt_len, &stripped_pt, &stripped_pt_len) != 0) {
        printf("ERROR: Strip padding error\n");
        ret = CRYPTOPALS_FAIL;
        goto err_strip_pad;
    }

    // Output
    printf("\nThe stripped plaintext in hex is: ");
    print_bytes(stripped_pt, stripped_pt_len);

err_strip_pad:
    free(stripped_pt);
err_apply_pad:
    free(padded_pt);
    return ret;
}
