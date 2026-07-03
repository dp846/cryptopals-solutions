// Detect single-character XOR

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"

/**
 * Will find the most likely message given an array of single byte xor-ed hex ciphertext strings
 */
int find_encrypted_line(char** hex_lines, size_t num_lines, uint8_t** most_likely_message, size_t line_length) {

    double highest_score = 0.0;
    size_t ct_length = strlen(hex_lines[0]) / 2;
    uint8_t* possible_message = NULL;

    if ((*most_likely_message = calloc(ct_length, sizeof(uint8_t))) == NULL) {
        printf("ERROR: malloc best message buffer\n");
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    char* current_line = NULL;
    uint8_t* ct_buffer = NULL;
    uint8_t key_byte = 0;

    for (size_t i = 0; i < num_lines; i++) {
        current_line = hex_lines[i];

        if ((ct_buffer = calloc(ct_length, sizeof(uint8_t))) == NULL) {
            printf("ERROR: malloc buffer\n");
            free(*most_likely_message);
            return CRYPTOPALS_ERR_ALLOC_FAIL;
        }

        if (hex_to_bytes(current_line, ct_buffer) != 0) {
            printf("ERROR: hex conversion\n");
            free(*most_likely_message);
            free(ct_buffer);
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }

        possible_message = single_byte_xor_decryption(ct_buffer, ct_length, &key_byte);
        if (possible_message == NULL) {
            printf("ERR: single byte xor decryption\n");
            free(*most_likely_message);
            free(ct_buffer);
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }

        double score = score_text(possible_message, line_length);
        if (score > highest_score) {
            highest_score = score;
            memcpy(*most_likely_message, possible_message, ct_length);
        }

        // Frees after each iteration
        free(possible_message);
        free(ct_buffer);
    }

    return CRYPTOPALS_SUCCESS;
}

int main(void) {
    printf("Task 4: Detect single-character XOR \n");

    int ret = CRYPTOPALS_SUCCESS;

    char** lines = NULL;
    size_t num_lines = 0;

    uint8_t* decrypted_result = NULL;

    // Read file contents
    if (read_lines_from_file("task04.txt", &lines, &num_lines) != 0) {
        printf("Error reading lines from the file.\n");
        ret = CRYPTOPALS_FAIL;
        goto err_file_read;
    }

    // Call find encrypted line
    if (find_encrypted_line(lines, num_lines, &decrypted_result, strlen(lines[0])) != 0) {
        printf("ERROR: error finding the encrypted line");
        ret = CRYPTOPALS_FAIL;
        goto err_line_decrypt;
    } else {
        for (size_t i = 0; i < strlen(lines[0]) / 2; i++) {
            printf("%c", decrypted_result[i]);
        }
    }

err_line_decrypt:
    if (decrypted_result) {
        free(decrypted_result);
    }
err_file_read:
    free(lines);
    return ret;
}
