// Byte-at-a-time ECB decryption (Simple)

#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"
#include "zero_memory.h"

#define BLOCK_SIZE 16
#define MAX_BUFFER_SIZE 4096

uint8_t KEY[BLOCK_SIZE];

/* Oracle to encrypt a secret message with an attacker controlled prefix*/
int aes_128_ecb_encryption_oracle(uint8_t* prefix, size_t prefix_len, uint8_t** ciphertext, size_t* ciphertext_len) {

    // Declare and decode the secret message
    const char* b64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyB"
                             "qdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    uint8_t* decoded_secret = NULL;
    size_t secret_len = 0;

    // Convert base64 to bytes
    if (base64_to_bytes((const uint8_t*)b64_secret, strlen(b64_secret), &decoded_secret, &secret_len) != 0) {
        printf("ERROR: Base 64 conversion failed");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Add prefix to the secret message
    size_t combined_pt_len = prefix_len + secret_len;
    uint8_t combined_pt[combined_pt_len];
    memcpy(combined_pt, prefix, prefix_len);
    memcpy(combined_pt + prefix_len, decoded_secret, secret_len);

    // Encrypt using ECB
    if (aes_ecb_encrypt(combined_pt, combined_pt_len, KEY, ciphertext, ciphertext_len) != 0) {
        printf("ERROR: Encryption ECB\n");
        free(decoded_secret);
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    free(decoded_secret);
    return CRYPTOPALS_SUCCESS;
}

/* Finds the block size and the secret length*/
int find_block_size_secret_length(size_t* block_size, size_t* secret_len) {

    size_t initial_ct_len = 0;
    size_t new_ct_len = 0;
    uint8_t* ciphertext = NULL;

    // Find the initial length of calling the oracle
    uint8_t input[] = {'A'};
    size_t input_len = 1;
    if (aes_128_ecb_encryption_oracle(input, input_len, &ciphertext, &initial_ct_len) != 0) {
        printf("ERROR: Failed oracle");
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    // Loop through, have a buffer to store '00', then '000' ...
    for (size_t i = 1; i < 1000; i++) {

        // Data buffer for input 0's
        uint8_t data[i];
        memset(data, 'A', i);

        // Do encryption
        if (aes_128_ecb_encryption_oracle(data, i, &ciphertext, &new_ct_len) != 0) {
            printf("ERROR: Failed oracle");
            free(ciphertext);
            return CRYPTOPALS_ERR_ENCRYPT;
        }

        free(ciphertext);
        ciphertext = NULL;

        // If the new_ct_len is > last_ct_len
        if (new_ct_len > initial_ct_len) {
            *block_size = new_ct_len - initial_ct_len;  // Block size s the difference between the two lengths
            *secret_len = new_ct_len - i - *block_size; // Secret length is -> secret_length = new_ct_len - num 0's - block_size
            break;
        }
    }

    free(ciphertext);
    return CRYPTOPALS_SUCCESS;
}

/* Decrypts ECB ciphertext byte by byte*/
int byte_by_byte_ecb_decryption(const size_t block_size, const size_t secret_len, uint8_t* secret_message) {

    if (block_size == 0) {
        printf("ERROR: Block size is zero\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    if (secret_len == 0 || secret_len > MAX_BUFFER_SIZE) {
        printf("ERROR: Secret length not in valid range\n");
        return CRYPTOPALS_ERR_OVERFLOW;
    }

    printf("Running decryption...\n\n");

    uint8_t decrypted[secret_len];
    size_t bytes_decrypted = 0;

    uint8_t* first_ct = NULL;
    uint8_t* second_ct = NULL;
    size_t ct_result_len = 0;

    for (size_t block_number = 1; block_number < (secret_len / block_size) + 2; block_number++) {

        // Loop through the byte index being decrypted
        for (size_t i = 0; i < block_size; i++) {

            size_t a_len = block_size - i - 1;

            // Check for array range issues before assignment
            if (a_len > MAX_BUFFER_SIZE) {
                printf("ERROR: Prefix length not in valid range\n");
                return CRYPTOPALS_ERR_LENGTH;
            }

            // VIOLATION CERT ARR32-C: a_len being 0 is valid. Code should be fine as I never access elements in the array if a_len is 0
            uint8_t a_prefix[a_len];
            memset(a_prefix, 'A', a_len);

            // Call the oracle with only A's
            if (aes_128_ecb_encryption_oracle(a_prefix, a_len, &first_ct, &ct_result_len) != 0) {
                printf("ERROR: Oracle failure\n");
                free(first_ct);
                free(second_ct);
                return CRYPTOPALS_ERR_ENCRYPT;
            }

            // Loop through all possible byte values
            for (int byte_val = 0; byte_val <= UINT8_MAX; byte_val++) {

                uint8_t test_input_block[block_size * block_number];

                memcpy(test_input_block, a_prefix, a_len); // Add the A's

                if (bytes_decrypted > 0) {
                    memcpy(test_input_block + a_len, decrypted, bytes_decrypted); // Add the bytes decrypted so far (if there are some)
                }

                memset(test_input_block + a_len + bytes_decrypted, byte_val, 1); // Add the final byte value

                // Call the oracle with the test input block I crafted
                if (aes_128_ecb_encryption_oracle(test_input_block, block_size * block_number, &second_ct, &ct_result_len) != 0) {
                    printf("ERROR: Oracle failure\n");
                    free(first_ct);
                    free(second_ct);
                    return CRYPTOPALS_ERR_ENCRYPT;
                }

                // Check if the ct blocks match
                if (memcmp(first_ct, second_ct, block_size * block_number) == 0) {
                    decrypted[(block_number - 1) * block_size + i] = byte_val;
                    bytes_decrypted += 1;
                    break;
                }

                // Free the ct generated by this byte value given it did not match
                free(second_ct);
                second_ct = NULL;
            }

            // Free the ct generated by the A's block
            free(first_ct);
            first_ct = NULL;

            // Check if the full message has been decrypted
            if (bytes_decrypted >= secret_len) {
                memcpy(secret_message, decrypted, secret_len);

                // Cleanup
                if (second_ct) {
                    free(second_ct);
                }

                return CRYPTOPALS_SUCCESS;
            }
        }
    }

    printf("ERROR: Decryption failed - message not found\n");
    return CRYPTOPALS_ERR_DECRYPT;
}

int main(void) {

    int ret = CRYPTOPALS_SUCCESS;

    // Generate a plaintext that would result in repeated blocks
    size_t plaintext_len = 1000;
    uint8_t plaintext[plaintext_len];

    uint8_t* ct_result = NULL;
    size_t ct_result_len = 0;

    // Generate a random unknown key in a variable for oracle to use repeatedly
    if (generate_random_key(KEY, BLOCK_SIZE) != 0) {
        printf("ERROR: Key generation fail\n");
        return CRYPTOPALS_FAIL;
    }

    // Output key
    printf("Random 16 byte key: ");
    print_bytes(KEY, BLOCK_SIZE);

    // Find the block size and secret length
    size_t block_size = 0;
    size_t secret_len = 0;

    if (find_block_size_secret_length(&block_size, &secret_len) != 0) {
        printf("ERROR: Could not find block size\n");

// Zero out the key in memory after use
#ifdef USE_LIBSODIUM
        sodium_memzero(KEY, BLOCK_SIZE);
#else
        zero_memory(KEY, BLOCK_SIZE, BLOCK_SIZE);
#endif

        return CRYPTOPALS_FAIL;
    }

    printf("\nBlock size: %ld\n", block_size);
    printf("Secret length: %ld\n", secret_len);

    uint8_t decrypted_message[secret_len];

    printf("\nLooking for the use of ECB... \n");

    // Encrypt
    if (aes_128_ecb_encryption_oracle(plaintext, plaintext_len, &ct_result, &ct_result_len) != 0) {
        printf("ERROR: Oracle failure\n");
        ret = CRYPTOPALS_FAIL;
        goto err_oracle;
    }

    // Check for duplicate blocks and thus use of ECB
    if (find_duplicate_blocks(ct_result, ct_result_len)) {
        printf("PASS: Detected use of ECB\n\n");
    } else {
        printf("FAIL: Did not detect use of ECB\n\n");
        ret = CRYPTOPALS_FAIL;
        goto err_ecb_detection;
    }

    // Run the byte by byte decryption process
    if (byte_by_byte_ecb_decryption(block_size, secret_len, decrypted_message) != 0) {
        printf("ERROR: Failed decryption process\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decrypt;
    }

    // Output the discovered secret message
    printf("Secret message: ");
    for (size_t i = 0; i < secret_len; i++) {
        printf("%c", decrypted_message[i]);
    }
    printf("\n");

err_decrypt:
err_ecb_detection:
err_oracle:
    free(ct_result);

// Zero out the key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(KEY, BLOCK_SIZE);
#else
    zero_memory(KEY, BLOCK_SIZE, BLOCK_SIZE);
#endif

    return ret;
}
