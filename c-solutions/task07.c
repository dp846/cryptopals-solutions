// AES in ECB mode

#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"

int main(void) {
    printf("Task 7: AES in ECB mode \n");

    int ret = CRYPTOPALS_SUCCESS;

    char** lines = NULL;
    size_t num_lines = 0;
    size_t file_len = 0;

    uint8_t* decoded_buffer = NULL;
    size_t decoded_len = 0;

    uint8_t key[] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    uint8_t* pt_result = NULL;
    size_t pt_result_len = 0;
    uint8_t* ct_result = NULL;
    size_t ct_result_len = 0;

    char* b64result = NULL;

    uint8_t* stripped_pt = NULL;
    size_t stripped_pt_len = 0;

    // Read the file contents
    if (read_lines_from_file("task07.txt", &lines, &num_lines) != 0) {
        printf("ERROR: Could not read file contents\n");
        ret = CRYPTOPALS_FAIL;
        goto err_file_read;
    }

    // Concatenate the lines
    uint8_t* b64_file_data;
    if ((b64_file_data = concatenate_lines_to_bytes(lines, num_lines, &file_len)) == NULL) {
        printf("ERROR: Failed to concatenate the base64 lines\n");
        ret = CRYPTOPALS_FAIL;
        goto err_concat_lines;
    }

    // Convert base64 to bytes
    if (base64_to_bytes(b64_file_data, file_len, &decoded_buffer, &decoded_len) != 0) {
        printf("ERROR: Base 64 conversion failed");
        ret = CRYPTOPALS_FAIL;
        goto err_b64_bytes;
    }

    // Perform the decryption
    printf("Performing decryption... \n\n");
    if (aes_ecb_decrypt(decoded_buffer, decoded_len, key, &pt_result, &pt_result_len) != 0) {
        printf("FAILED\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decryption;
    }

    // Strip padding off plaintext
    if (strip_pkcs7_padding(pt_result, pt_result_len, &stripped_pt, &stripped_pt_len) != 0) {
        printf("ERROR: Strip padding error\n");
        ret = CRYPTOPALS_FAIL;
        goto err_strip_pad;
    }

    // Output the result of decryption
    printf("The decrypted result was: \n\n");
    for (size_t i = 0; i < stripped_pt_len; i++) {
        printf("%c", stripped_pt[i]);
    }

    // Re-encrypt result to see if it matches the contents of the text file
    if (aes_ecb_encrypt(stripped_pt, stripped_pt_len, key, &ct_result, &ct_result_len) != 0) {
        printf("FAILED\n");
        ret = CRYPTOPALS_FAIL;
        goto err_encryption;
    }

    b64result = bytes_to_base64(ct_result, ct_result_len);
    if (!b64result) {
        printf("ERROR: Failed Malloc for b64 result");
        ret = CRYPTOPALS_FAIL;
        goto err_malloc_result;
    }

    printf("\nThe re-encrypted base64-ed result (should match task07.txt) was: \n\n");
    printf("%s\n\n", b64result);

    free(b64result);
err_malloc_result:
err_encryption:
    free(ct_result);
err_strip_pad:
    free(stripped_pt);
err_decryption:
    free(pt_result);
err_b64_bytes:
    free(decoded_buffer);
err_concat_lines:
    free(b64_file_data);
err_file_read:
    free(lines);
    return ret;
}
