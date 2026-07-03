#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "error_codes.h"
#include "file_utils.h"

int read_lines_from_file(const char* filename, char*** lines_out, size_t* num_lines_out) {

    // Open the file
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("ERROR: Failed to open the file\n");
        return CRYPTOPALS_ERR_FILE_OPEN;
    }

    char** lines = NULL;
    size_t num_lines = 0;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        if (read != -1 && read > 0 && line[read - 1] == '\n') {
            line[read - 1] = '\0'; // Strip the newline
        }

        // Check if the operations will wrap before the realloc
        if (num_lines > (SIZE_MAX - 1) || num_lines > (SIZE_MAX / sizeof(char*) - 1)) {
            printf("ERROR: Wrapping occured\n");

            // Cleanup
            free(line);
            for (size_t i = 0; i < num_lines; ++i) {
                free(lines[i]);
            }
            free(lines);

            // Close file
            if (fclose(file) == EOF) {
                printf("ERROR: Failed to close the file\n");
                return CRYPTOPALS_ERR_FILE_CLOSE;
            }
            return CRYPTOPALS_ERR_WRAPPING;
        }

        // Realloc for another line being added
        char** temp = realloc(lines, (num_lines + 1) * sizeof(char*));
        if (temp == NULL) {
            printf("ERROR: Failed to realloc\n");

            // Cleanup
            free(line);
            for (size_t i = 0; i < num_lines; ++i) {
                free(lines[i]);
            }
            free(lines);

            // Close file
            if (fclose(file) == EOF) {
                printf("ERROR: Failed to close the file\n");
                return CRYPTOPALS_ERR_FILE_CLOSE;
            }
            return CRYPTOPALS_ERR_ALLOC_FAIL;
        }

        lines = temp;
        lines[num_lines] = line;
        num_lines++;

        line = NULL;
        len = 0;
    }

    // Close file
    if (fclose(file) == EOF) {
        printf("ERROR: Failed to close the file\n");
        for (size_t i = 0; i < num_lines; ++i) {
            free(lines[i]);
        }
        free(lines);
        return CRYPTOPALS_ERR_FILE_CLOSE;
    }

    *lines_out = lines;
    *num_lines_out = num_lines;

    return CRYPTOPALS_SUCCESS;
}

uint8_t* concatenate_lines_to_bytes(char** lines, size_t num_lines, size_t* result_len) {

    // Determine the total length of the concatenated strings
    *result_len = 0;
    for (size_t i = 0; i < num_lines; i++) {
        size_t line_len = strlen(lines[i]);
        if (*result_len > SIZE_MAX - line_len) { // Check for wrapping
            return NULL;
        }
        *result_len += line_len;
    }

    // Check for 0 length
    if (*result_len == 0) {
        return NULL;
    }

    // Allocate memory for the result
    uint8_t* result = NULL;
    if ((result = malloc(*result_len)) == NULL) {
        return NULL; // Memory allocation failed
    }

    // Copy each line to the result array
    size_t pos = 0;
    for (size_t i = 0; i < num_lines; i++) {
        size_t line_len = strlen(lines[i]);
        if (pos > SIZE_MAX - line_len) { // Check for wrapping
            free(result);
            return NULL;
        }
        memcpy(result + pos, lines[i], line_len);
        pos += line_len;
    }

    return result;
}
