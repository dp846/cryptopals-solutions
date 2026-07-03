// Byte-at-a-time ECB decryption (Simple)

#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
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
#define MAX_PREFIX_LEN 100

// All defined globally, so I can generate them once and then the oracle can use them repeatedly
uint8_t KEY[BLOCK_SIZE];
uint8_t PREFIX[MAX_PREFIX_LEN];
size_t PREFIX_LENGTH = 0;

/*Figure out how many blocks of BLOCK_SIZE are identical*/
int same_block_count(const uint8_t* buffer1, const uint8_t* buffer2, const size_t buffers_len) {

    // Check for NULL
    if (!buffer1 || !buffer2) {
        printf("ERROR: NULL pointer error\n");
        return CRYPTOPALS_FAIL_N;
    }

    // Check for invalid length
    if (buffers_len % BLOCK_SIZE != 0) {
        printf("ERROR: buffers_len is not a multiple of BLOCK_SIZE\n");
        return CRYPTOPALS_FAIL_N;
    }

    // Count the identical blocks
    int identical_blocks = 0;
    for (size_t i = 0; i < buffers_len; i += BLOCK_SIZE) {
        if (memcmp(buffer1 + i, buffer2 + i, BLOCK_SIZE) == 0) {

            // Check for overflow before incrementing
            if (identical_blocks == INT_MAX) {
                printf("ERROR: Overflow\n");
                return CRYPTOPALS_FAIL_N;
            }
            identical_blocks++;
        }
    }
    return identical_blocks;
}

/*Oracle to encrypt in ECB with a random prefix of a random length*/
int aes_ecb_orcale_random_prefix(const uint8_t* controlled, const size_t controlled_len, uint8_t** ciphertext, size_t* ciphertext_len) {

    // Declare and decode the secret message
    const char* b64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyB"
                             "qdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    uint8_t* decoded_secret = NULL;
    size_t secret_len = 0;

    // Convert the base64 to bytes
    if (base64_to_bytes((const uint8_t*)b64_secret, strlen(b64_secret), &decoded_secret, &secret_len) != 0) {
        printf("ERROR: Base 64 conversion failed");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Assign VLA for new plaintext with prefix and suffix added
    size_t combined_len = PREFIX_LENGTH + controlled_len + secret_len;
    uint8_t combined[combined_len];

    // Copy the random prefix, attacker controlled bytes, and the secret message bytes into a bytes array
    memcpy(combined, PREFIX, PREFIX_LENGTH);
    memcpy(combined + PREFIX_LENGTH, controlled, controlled_len);
    memcpy(combined + PREFIX_LENGTH + controlled_len, decoded_secret, secret_len);

    // Encrypt using ECB
    if (aes_ecb_encrypt(combined, combined_len, KEY, ciphertext, ciphertext_len) != 0) {
        printf("ERROR: Encryption ECB\n");
        free(decoded_secret);
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    free(decoded_secret);
    return CRYPTOPALS_SUCCESS;
}

/*Finds the prefix length and the secret message length by repeated oracle calls*/
int find_prefix_secret_lengths(size_t* prefix_len, size_t* secret_len) {

    uint8_t* prev_ciphertext = NULL;
    size_t prev_ciphertext_len = 0;
    uint8_t* cur_ciphertext = NULL;
    size_t cur_ciphertext_len = 0;

    uint8_t attacker_input[BLOCK_SIZE]; // Should be a maximum of BLOCK_SIZE for first step
    memset(attacker_input, 'A', BLOCK_SIZE);
    size_t attacker_input_len = 0; // I will just control how much of the attacker array will be fed into the oracle with this

    // Encrypt using oracle with no input  ->   prev_ciphertext
    if (aes_ecb_orcale_random_prefix(attacker_input, attacker_input_len, &prev_ciphertext, &prev_ciphertext_len) != 0) {
        printf("ERROR: Oracle failed\n");
        return CRYPTOPALS_FAIL;
    }

    // Encrypt using oracle with 1 byte input  ->   cur_ciphertext
    attacker_input_len = 1;
    if (aes_ecb_orcale_random_prefix(attacker_input, attacker_input_len, &cur_ciphertext, &cur_ciphertext_len) != 0) {
        printf("ERROR: Oracle failed\n");
        return CRYPTOPALS_FAIL;
    }

    // Discover how many blocks the prefix spans
    int num_identical = same_block_count(prev_ciphertext, cur_ciphertext, prev_ciphertext_len); // The prefix must cover this entire block
    printf("The number of same blocks is %d\n", num_identical);

    size_t ct_len_no_padding = 0;            // The ct length with a full block of padding removed
    size_t len_for_increase = 0;             // The attacker input required to increase the number of blocks
    size_t controlled_len_needed = SIZE_MAX; // Large value as I take the minimum later on
    size_t new_controlled_len = 0;

    // Loop through and keep adding a byte to the plaintext until an overspilled block of ciphertext
    for (size_t i = 1; i <= BLOCK_SIZE + 1; i++) {

        // Create the input A's
        attacker_input_len = i;
        memset(attacker_input, 'A', attacker_input_len);

        // Encrypt using oracle with +1 input length  ->   cur_ciphertext
        if (aes_ecb_orcale_random_prefix(attacker_input, attacker_input_len, &cur_ciphertext, &cur_ciphertext_len) != 0) {
            printf("ERROR: Oracle failed\n");
            return CRYPTOPALS_FAIL;
        }

        // Check that the ct length mismatch is new and the new byte caused an increase in the number of blocks of ciphertext
        if (prev_ciphertext_len != cur_ciphertext_len && ct_len_no_padding == 0) {
            ct_len_no_padding = prev_ciphertext_len;
            len_for_increase = attacker_input_len;
        }

        // Check whether a new block of ct now matches - the input must have spilled over into a new block
        if (memcmp(prev_ciphertext + (num_identical * BLOCK_SIZE), cur_ciphertext + (num_identical * BLOCK_SIZE), BLOCK_SIZE) == 0) {

            // Takes the minimum of the existing value for the length and a new one calculated
            new_controlled_len = attacker_input_len - 1;
            controlled_len_needed = (new_controlled_len < controlled_len_needed) ? new_controlled_len : controlled_len_needed;
        }

        memcpy(prev_ciphertext, cur_ciphertext, prev_ciphertext_len);
    }

    *prefix_len = ((num_identical + 1) * BLOCK_SIZE) - controlled_len_needed;
    *secret_len = ct_len_no_padding - len_for_increase - *prefix_len;

    return CRYPTOPALS_SUCCESS;
}

/*Decrypts ECB byte by byte - similar process to 12 but prefix is random*/
int byte_by_byte_ecb_harder(const size_t prefix_len, const size_t secret_len, uint8_t* decrypted_message) {

    printf("Running decryption...\n\n");
    size_t num_decrypted = 0;

    uint8_t* expected_ct = NULL;
    uint8_t* test_ct = NULL;
    size_t expected_ct_len = 0;
    size_t test_ct_len = 0;

    uint8_t controlled_bytes[BLOCK_SIZE]; // As a max it should be block size in length
    memset(controlled_bytes, 'A', BLOCK_SIZE);
    size_t controlled_len = 0;

    for (size_t i = 0; i < secret_len; i++) {

        // Will circle all the vals of block size to figure out the length of controlled bytes to input such that the byte of the secret currently
        // being decrypted is in the final position of a block.
        if (num_decrypted > SIZE_MAX - prefix_len) {
            printf("ERROR: Overflow\n");
            return CRYPTOPALS_ERR_OVERFLOW;
        }
        size_t mod_result = (prefix_len + num_decrypted) % BLOCK_SIZE;           // 0 to 15 (for BLOCK_SIZE 16)
        size_t to_subtract = (mod_result < BLOCK_SIZE - 1) ? mod_result + 1 : 0; // Adding 1 to 15 should wrap to 0 (for BLOCK_SIZE 16)
        controlled_len = (BLOCK_SIZE - to_subtract);

        // Encrypt to get the EXPECTED:
        if (aes_ecb_orcale_random_prefix(controlled_bytes, controlled_len, &expected_ct, &expected_ct_len) != 0) {
            printf("ERROR: Oracle failed\n");
            return CRYPTOPALS_FAIL;
        }

        for (size_t byte_val = 0; byte_val < 256; byte_val++) {

            size_t full_controlled_len = controlled_len + num_decrypted + 1;
            uint8_t controlled_with_byte[full_controlled_len];

            // Copy these values into the array
            memcpy(controlled_with_byte, controlled_bytes, controlled_len);                  // The 0-15 zeros..
            memcpy(controlled_with_byte + controlled_len, decrypted_message, num_decrypted); // The decrypted so far...
            controlled_with_byte[full_controlled_len - 1] = (uint8_t)byte_val;

            // Encrypt to get ct to TEST against EXPECTED:
            if (aes_ecb_orcale_random_prefix(controlled_with_byte, full_controlled_len, &test_ct, &test_ct_len) != 0) {
                printf("ERROR: Oracle failed\n");
                return CRYPTOPALS_FAIL;
            }

            size_t block_index = (prefix_len + controlled_len + num_decrypted) / BLOCK_SIZE;
            size_t block_offset = block_index * BLOCK_SIZE;

            // Compare the test ct and the expected ct blocks up to correct block number
            if (memcmp(expected_ct + block_offset, test_ct + block_offset, BLOCK_SIZE) == 0) {

                // Add the resulting byte to the secret message decrypted so far
                decrypted_message[num_decrypted] = (uint8_t)byte_val;
                num_decrypted++;
                break;
            }
            free(test_ct);
        }
        free(expected_ct);
    }

    return CRYPTOPALS_SUCCESS;
}

int main(void) {

    int ret = CRYPTOPALS_SUCCESS;

    size_t prefix_len = 0;
    size_t secret_len = 0;
    uint8_t* secret_message = NULL;

    // Generate a random length for the prefix
    uint8_t rand_byte = 0;
    if (getentropy(&rand_byte, 1) == -1) {
        printf("ERROR: Unable to generate random number\n");
        ret = CRYPTOPALS_ERR_MISCELLANEOUS;
        goto err_rand_gen;
    }
    PREFIX_LENGTH = 2 + ((size_t)rand_byte % 32);

    // Generate random (consistent) prefix byte contents for use across multiple oracle calls
    if (getentropy(PREFIX, PREFIX_LENGTH) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        ret = CRYPTOPALS_ERR_MISCELLANEOUS;
        goto err_prefix_gen;
    }

    // Generate a random (consistent) key for use across multiple oracle calls
    if (getentropy(KEY, BLOCK_SIZE) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        ret = CRYPTOPALS_ERR_MISCELLANEOUS;
        goto err_key_gen;
    }

    // Find out the prefix length and the secret length
    if (find_prefix_secret_lengths(&prefix_len, &secret_len) != 0) {
        printf("ERROR: Find lengths failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_find_lengths;
    }
    printf("The prefix length is %ld\n", prefix_len);
    printf("The secret length is %ld\n", secret_len);

    // Allocate memory for secret message
    secret_message = calloc(secret_len, sizeof(uint8_t));
    if (!secret_message) {
        printf("ERROR: Memory allocation failed\n");
        goto err_calloc_secret;
    }

    // Do decryption
    if (byte_by_byte_ecb_harder(prefix_len, secret_len, secret_message) != 0) {
        printf("ERROR: Failed decryption\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decrypt;
    }

    // Ouput secret contents
    printf("Decrypted secret message: \n");
    for (size_t i = 0; i < secret_len; i++) {
        printf("%c", secret_message[i]);
    }

err_decrypt:
    free(secret_message);
err_calloc_secret:
err_find_lengths:
err_key_gen:

// Zero out the key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(KEY, BLOCK_SIZE);
#else
    zero_memory(KEY, BLOCK_SIZE, BLOCK_SIZE);
#endif

err_prefix_gen:
err_rand_gen:
    return ret;
}
