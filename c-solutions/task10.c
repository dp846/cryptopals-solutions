// Implement CBC mode

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

    int ret = CRYPTOPALS_SUCCESS;

    // Initialising variables
    char** lines = NULL;
    size_t num_lines = 0;
    size_t file_len = 0;

    uint8_t* decoded_buffer = NULL;
    size_t decoded_len = 0;

    uint8_t key[] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    uint8_t init_vec[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    uint8_t* decrypted_plaintext = NULL;
    size_t decrypted_plaintext_len = 0;

    uint8_t* encrypted_result;
    size_t encrypted_result_len;

    // Read the file contents
    if (read_lines_from_file("task10.txt", &lines, &num_lines) != 0) {
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

    // Output
    printf("Encrypted file data in hex:  ");
    print_bytes(decoded_buffer, decoded_len);

    // Do decryption using aes_cbc_decrypt
    if (aes_cbc_decrypt(key, decoded_buffer, decoded_len, init_vec, &decrypted_plaintext, &decrypted_plaintext_len) != 0) {
        printf("ERROR: CBC decryption failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decryption;
    }

    // Print result byte by byte to build up a string
    printf("\nDecrypted plaintext:\n");
    for (size_t i = 0; i < decrypted_plaintext_len; ++i) {
        printf("%c", decrypted_plaintext[i]);
    }
    printf("\n");

    // Now encrypt using aes_cbc_encrypt
    if (aes_cbc_encrypt(key, decrypted_plaintext, decrypted_plaintext_len, init_vec, &encrypted_result, &encrypted_result_len) != 0) {
        printf("ERROR: CBC encryption failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decryption;
    }

    // Output
    printf("\nThe re-encrypted file data in hex - this should match the above hex before decryption:  ");
    print_bytes(encrypted_result, encrypted_result_len);

    free(encrypted_result);

err_decryption:
    free(decrypted_plaintext);
err_b64_bytes:
    free(decoded_buffer);
err_concat_lines:
    free(b64_file_data);
err_file_read:
    free(lines);
    return ret;
}
