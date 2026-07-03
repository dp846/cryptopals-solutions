// Break repeating-key XOR

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"

// Values for use in this task
#define MIN_KEY_SIZE 2
#define MAX_KEY_SIZE 41
#define NUM_OF_KEYSIZES 4
#define MAX_BUFFER_SIZE 4096

/**
 * Finds the hamming distance between two buffers of bytes. Expects the length of the two buffers to match
 */
int find_hamming_distance(const uint8_t* buffer1, const uint8_t* buffer2, size_t buffer_len, uint32_t* result) {

    // Check for NULL pointers
    if (buffer1 == NULL || buffer2 == NULL || result == NULL) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    // Check for zero length
    if (buffer_len == 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Check for a size that would take a lot of stack memory (predefined above)
    if (buffer_len > MAX_BUFFER_SIZE) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Perform the XOR operation
    uint8_t xor_result[buffer_len];
    memset(xor_result, 0, buffer_len);
    if (xor_on_bytes(buffer1, buffer2, xor_result, buffer_len) != 0) {
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Calculate the distance
    uint32_t distance = 0;
    for (size_t i = 0; i < buffer_len; i++) {
        for (size_t j = 0; j < 8; j++) {
            if (xor_result[i] & (1 << j)) {
                if (distance == UINT32_MAX) {
                    return CRYPTOPALS_ERR_OVERFLOW;
                }
                distance++;
            }
        }
    }

    *result = distance;
    return 0;
}

/**
 * Discovers the top N most likely key lengths given a buffer of bytes for repeating key XOR
 */
int possible_key_lengths(const uint8_t* bytes_file_data, size_t data_len, int* top_n_keys, size_t* num_keys) {

    // Check for any NULL pointers
    if (!bytes_file_data || !top_n_keys || !num_keys) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    double distances_and_keys[MAX_KEY_SIZE - MIN_KEY_SIZE][2];

    // Calculate normalised dist for each of the key sizes
    for (size_t key_size = MIN_KEY_SIZE; key_size < MAX_KEY_SIZE; key_size++) {
        uint32_t total_distance = 0;

        if (3 * key_size > data_len) // Check if the number of blocks I'm checking exceeds the bounds of the array of data
        {
            printf("ERROR: OoB for given key size and block count\n");
            return CRYPTOPALS_ERR_OUTOFBOUNDS;
        }

        for (int i = 0; i < 3; i++) { // Comparing only 1-2, 2-3, 3-4 chunks
            uint32_t distance;
            if (find_hamming_distance(&bytes_file_data[i * key_size], &bytes_file_data[(i + 1) * key_size], key_size, &distance) != 0) {
                printf("ERROR: Hamming distance failure\n");
                return CRYPTOPALS_ERR_MISCELLANEOUS;
            }

            // Check if the addition would wrap before doing it
            if (total_distance > (UINT32_MAX - distance)) {
                printf("ERROR: Addition would wrap\n");
                return CRYPTOPALS_ERR_OVERFLOW;
            }
            total_distance += distance;
        }

        const size_t MAX_SAFE_SIZE_T_FOR_DOUBLE = (size_t)1 << 53; // 2^53

        // Check if key size being cast as double loses data
        if (key_size >= MAX_SAFE_SIZE_T_FOR_DOUBLE) {
            printf("ERROR: Loss of precision\n");
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }

        double normalized_distance = (double)total_distance / key_size;
        distances_and_keys[key_size - MIN_KEY_SIZE][0] = normalized_distance;
        distances_and_keys[key_size - MIN_KEY_SIZE][1] = key_size;
    }

    // Bubble sort because it's simple get working and show!
    for (int i = 0; i < (MAX_KEY_SIZE - MIN_KEY_SIZE) - 1; i++) {
        for (int j = 0; j < (MAX_KEY_SIZE - MIN_KEY_SIZE) - i - 1; j++) {
            if (distances_and_keys[j][0] > distances_and_keys[j + 1][0]) {
                double temp1 = distances_and_keys[j][0];
                double temp2 = distances_and_keys[j][1];
                distances_and_keys[j][0] = distances_and_keys[j + 1][0];
                distances_and_keys[j][1] = distances_and_keys[j + 1][1];
                distances_and_keys[j + 1][0] = temp1;
                distances_and_keys[j + 1][1] = temp2;
            }
        }
    }

    // Retrieve top N keysizes
    for (int i = 0; i < NUM_OF_KEYSIZES; i++) {
        top_n_keys[i] = (int)distances_and_keys[i][1];
    }
    *num_keys = NUM_OF_KEYSIZES;

    return CRYPTOPALS_SUCCESS;
}

/**
 * XOR decrypts a ciphertext with the key in a cyclic way for repeating key XOR
 */
int decrypt_with_key(const uint8_t* ciphertext, const size_t ciphertext_len, const uint8_t* key, const size_t key_len, uint8_t* plaintext) {

    // Check pointers
    if (!ciphertext || !key || !plaintext) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    // Check lengths
    if (ciphertext_len == 0 || key_len == 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Perform xor cyclic way
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }

    return CRYPTOPALS_SUCCESS;
}

int main(void) {
    printf("Task 6: Break repeating-key XOR \n");

    int ret = CRYPTOPALS_SUCCESS;

    char** lines = NULL;
    size_t num_lines = 0;
    size_t file_len = 0;

    uint8_t* decoded_buffer = NULL;
    size_t decoded_len = 0;

    int top_keys[NUM_OF_KEYSIZES];
    size_t num_keys = 0;

    double best_score = 0.0;
    uint8_t* best_message = NULL;
    uint8_t* key = NULL;

    // Read the file contents
    if (read_lines_from_file("task06.txt", &lines, &num_lines) != 0) {
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
        goto err_b64_decode;
    }

    // Find the most likely key lengths
    if (possible_key_lengths(decoded_buffer, decoded_len, top_keys, &num_keys) != 0) {
        printf("ERROR: Failed to get top keys\n");
        ret = CRYPTOPALS_FAIL;
        goto err_keys;
    }

    // Malloc for final result
    best_message = calloc(decoded_len, sizeof(uint8_t));
    if (!best_message) {
        printf("ERROR: Failed malloc\n");
        ret = CRYPTOPALS_FAIL;
        goto err_malloc_msg;
    }

    // Try the top N key sizes
    for (size_t key_index = 0; key_index < NUM_OF_KEYSIZES; key_index++) {

        int key_size = top_keys[key_index];

        // Work out the number of COMPLETE blocks
        int num_blocks = decoded_len / key_size;

        key = calloc(key_size, sizeof(uint8_t));
        if (key == NULL) {
            printf("ERROR: Failed to allocate memory for key\n");
            ret = CRYPTOPALS_FAIL;
            goto err_malloc_key;
        }

        for (int i = 0; i < key_size; i++) {
            uint8_t block[num_blocks];

            // Create a block with the ith byte of every key-sized block
            for (int j = 0; j < num_blocks; j++) {
                block[j] = decoded_buffer[j * key_size + i];
            }

            uint8_t best_key_byte = 0;
            uint8_t* decrypted_block = single_byte_xor_decryption(block, num_blocks, &best_key_byte);
            key[i] = best_key_byte;

            if (decrypted_block) {
                free(decrypted_block);
            }
        }

        // Output the most likely key for a key size
        printf("\nFor key size %d the best key was: ", key_size);
        for (int i = 0; i < key_size; i++) {
            printf("%c", key[i]);
        }
        printf("\n\n");

        uint8_t plaintext[decoded_len];

        if (decrypt_with_key(decoded_buffer, decoded_len, key, key_size, plaintext) != 0) {
            printf("ERROR: Failed to decrypt message\n");
            ret = CRYPTOPALS_FAIL;
            free(key);
            goto err_decrypt;
        }

        double current_score = score_text(plaintext, decoded_len);
        if (current_score > best_score) {
            best_score = current_score;
            memcpy(best_message, plaintext, decoded_len); // Copy the current best plaintext
        }

        free(key);
        key = NULL;
    }

    // Output contents of the mest message
    for (size_t i = 0; i < decoded_len; i++) {
        printf("%c", best_message[i]);
    }

err_decrypt:
err_malloc_key:
err_malloc_msg:
    free(best_message);
err_keys:
err_b64_decode:
    free(decoded_buffer);
    free(b64_file_data);
err_concat_lines:
err_file_read:
    free(lines);
    return ret;
}
