// An ECB/CBC detection oracle

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
#define MAX_BUFFER_SIZE 4096

/* Oracle to encrypt with ECB or CBC randomly*/
int encryption_orcale_ecb_or_cbc(const uint8_t* plaintext, size_t plaintext_len, uint8_t** ciphertext, size_t* ciphertext_len) {

    // Check for 0 length for plaintext
    if (plaintext_len == 0) {
        printf("ERROR: Plaintext length of 0");
        return CRYPTOPALS_ERR_LENGTH;
    }

    uint8_t key[BLOCK_SIZE] = {0};

    // Generate random key
    if (generate_random_key(key, BLOCK_SIZE) != 0) {
        printf("ERROR: Key generation");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Generate a random number between 5 and 10 for padding at the start and end
    size_t num_bytes = 3;
    uint8_t random_bytes[num_bytes];
    memset(random_bytes, 0, num_bytes);

    if (getentropy(random_bytes, 3) == -1) {
        printf("ERROR: Unable to generate random numbers");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }
    size_t prefix_len = 5 + (random_bytes[0] % 6);
    size_t suffix_len = 5 + (random_bytes[1] % 6);
    int ecb_or_cbc = (random_bytes[2] & 1);

    // Check for 0 lengths for prefix or suffix
    if (prefix_len == 0 || suffix_len == 0) {
        printf("ERROR: Length of 0\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Assign VLAs for prefix and suffix
    uint8_t prefix[prefix_len];
    memset(prefix, 0, prefix_len);
    uint8_t suffix[suffix_len];
    memset(suffix, 0, suffix_len);

    if (getentropy(prefix, prefix_len) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }
    if (getentropy(suffix, suffix_len) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    size_t new_plaintext_len = prefix_len + plaintext_len + suffix_len;

    // Check for VLA length being in valid range
    if (new_plaintext_len == 0 || new_plaintext_len > MAX_BUFFER_SIZE) {
        printf("ERROR: VLA length not in valid range\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Assign VLA for new plaintext with prefix and suffix added
    uint8_t new_plaintext[new_plaintext_len];

    // Copy the random prefix, original plaintext, and random suffix into the new plaintext
    memcpy(new_plaintext, prefix, prefix_len);
    memcpy(new_plaintext + prefix_len, plaintext, plaintext_len);
    memcpy(new_plaintext + prefix_len + plaintext_len, suffix, suffix_len);

    if (ecb_or_cbc) {
        printf("Encrypting in CBC...\n");

        uint8_t init_vec[BLOCK_SIZE];
        memset(init_vec, 0, BLOCK_SIZE);

        // Generate random IV
        if (generate_random_key(init_vec, BLOCK_SIZE) != 0) {
            printf("ERROR: IV generation");
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }

        // Now encrypt using aes_cbc_encrypt
        if (aes_cbc_encrypt(key, plaintext, plaintext_len, init_vec, ciphertext, ciphertext_len) != 0) {
            printf("ERROR: CBC encryption failed\n");
            return CRYPTOPALS_ERR_ENCRYPT;
        }
    } else {
        printf("Encrypting in ECB...\n");

        // Do encryption with aes_ecb_encrypt
        if (aes_ecb_encrypt(new_plaintext, new_plaintext_len, key, ciphertext, ciphertext_len) != 0) {
            printf("ERROR: Encryption ECB\n");
            return CRYPTOPALS_ERR_ENCRYPT;
        }
    }

    return 0;
}

int main(void) {

    uint8_t key[BLOCK_SIZE] = {0};

    // Generate random key
    if (generate_random_key(key, BLOCK_SIZE) != 0) {
        printf("ERROR: Key generation");
        return CRYPTOPALS_FAIL;
    }

    // Generate a plaintext that would result in repeated blocks
    size_t plaintext_len = 1000;
    uint8_t plaintext[plaintext_len];
    memset(plaintext, 0, plaintext_len);

    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;

    // Loop through and try the detection 10 times
    for (size_t i = 0; i < 10; i++) {
        encryption_orcale_ecb_or_cbc(plaintext, plaintext_len, &ciphertext, &ciphertext_len);

        if (find_duplicate_blocks(ciphertext, ciphertext_len)) {
            printf("Detected use of ECB\n\n");
        } else {
            printf("Detected use of CBC\n\n");
        }

        free(ciphertext);
        ciphertext = NULL;
    }

    // Zero out the key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(key, BLOCK_SIZE);
#else
    zero_memory(key, BLOCK_SIZE, BLOCK_SIZE);
#endif

    return CRYPTOPALS_SUCCESS;
}
