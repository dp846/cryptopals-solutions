// Detect AES in ECB mode

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"

#define BLOCK_SIZE 16

int main(void) {
    printf("Task 8: Detect AES in ECB mode \n");

    int ret = CRYPTOPALS_SUCCESS;

    char** lines = NULL;
    size_t num_lines = 0;

    char* hex_line = NULL;
    size_t bytes_len = 0;
    uint8_t* bytes_line = NULL;

    // Read the file contents
    if (read_lines_from_file("task08.txt", &lines, &num_lines) != 0) {
        printf("ERROR: Could not read file contents\n");
        ret = CRYPTOPALS_FAIL;
        goto err_read_file;
    }

    for (size_t i = 0; i < num_lines; i++) {
        hex_line = lines[i];
        bytes_len = strlen(lines[i]) / 2;

        bytes_line = calloc(bytes_len, sizeof(uint8_t));
        if (!bytes_line) {
            printf("ERROR: Failed calloc bytes\n");
            ret = CRYPTOPALS_FAIL;
            goto err_calloc_bytes;
        }

        // Hex convert to bytes
        if (hex_to_bytes(hex_line, bytes_line) != 0) {
            printf("ERROR: Hex conversion error\n");
            ret = CRYPTOPALS_FAIL;
            goto err_hex_bytes;
        }

        // See if there were duplicates
        if (find_duplicate_blocks(bytes_line, bytes_len) == 1) {
            printf("\nDuplicates found on line %ld. This means that ECB mode must have been used to encrypt\n", (i + 1));
        }

    err_hex_bytes:
        free(bytes_line);
        bytes_line = NULL;
    }

err_calloc_bytes:
err_read_file:
    if (lines) {
        for (size_t i = 0; i < num_lines; i++) {
            free(lines[i]);
        }
        free(lines);
    }
    return ret;
}
