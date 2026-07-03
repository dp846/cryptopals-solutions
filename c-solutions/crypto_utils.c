#include <ctype.h>
#include <limits.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "crypto_utils.h"
#include "error_codes.h"

#define BLOCK_SIZE 16
#define MAX_BUFFER_SIZE 4096

int xor_on_bytes(const uint8_t* buffer1, const uint8_t* buffer2, uint8_t* result_buffer, size_t length) {

    if (buffer1 && buffer2) {
        for (size_t i = 0; i < length; i++) {
            result_buffer[i] = buffer1[i] ^ buffer2[i]; // Bitwise xor for each index
        }
        return CRYPTOPALS_SUCCESS;
    }
    printf("ERROR: Null pointer on buffer");
    return CRYPTOPALS_ERR_NULL_PTR;
}

uint8_t* extend_key_repeated(const uint8_t* key, const size_t key_len, size_t extended_len) {

    // Check for 0 length key as modulo division is used
    if (key_len == 0) {
        printf("ERROR: Key length of 0\n");
        return NULL;
    }

    // Calloc
    uint8_t* repeated_key = calloc(extended_len, sizeof(uint8_t));
    if (!repeated_key) {
        printf("ERROR: Failed calloc for extended key\n");
        return NULL;
    }

    for (size_t i = 0; i < extended_len; i++) {
        repeated_key[i] = key[i % key_len];
    }

    return repeated_key;
}

double score_text(uint8_t* data, size_t length) {

    const double english_freq[26] = {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966,
                                     0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
                                     0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

    const double SPACE_FREQ = 0.13000;
    const double ALPHABETICAL_MULTIPLIER = 10.0;

    double score = 0.0;

    for (size_t i = 0; i < length; i++) {

        if (isascii(data[i])) {                        // Check if the character is of ASCII range
            int chr = tolower((unsigned char)data[i]); // Cast to unsigned char first

            if (chr >= 'a' && chr <= 'z') {
                score += ALPHABETICAL_MULTIPLIER * english_freq[chr - 'a'];
            } else if (chr == ' ') {
                score += ALPHABETICAL_MULTIPLIER * SPACE_FREQ;
            }
        }
    }
    return score;
}

uint8_t* single_byte_xor_decryption(uint8_t* ciphertext, size_t ciphertext_length, uint8_t* best_key_byte) {

    // Check if the max buffer size is exceeded for stack allocation, or if length is 0
    if (ciphertext_length > MAX_BUFFER_SIZE || ciphertext_length == 0) {
        printf("ERROR: VLA length error\n");
        return NULL;
    }

    uint8_t* best_plaintext = NULL;
    double highest_score = 0.0;

    for (int key = 0; key <= UINT8_MAX; key++) {

        uint8_t extended_key[ciphertext_length];
        memset(extended_key, key, ciphertext_length);

        // Calloc for a possible message and check for null
        uint8_t* possible_message = (uint8_t*)calloc(ciphertext_length, sizeof(uint8_t));
        if (!possible_message) {
            if (best_plaintext) { // Free if assigned
                free(best_plaintext);
            }
            return NULL;
        }

        if (xor_on_bytes(ciphertext, extended_key, possible_message, ciphertext_length) != 0) {
            printf("ERROR: XOR failed\n");

            if (best_plaintext) { // Free if assigned
                free(best_plaintext);
            }
            free(possible_message);

            return NULL;
        }

        double score = score_text(possible_message, ciphertext_length);

        if (score > highest_score) {
            if (best_plaintext != NULL) {
                free(best_plaintext);
            }
            highest_score = score;
            best_plaintext = possible_message;
            *best_key_byte = (uint8_t)key;
        } else {
            free(possible_message);
        }
    }

    return best_plaintext;
}

int find_duplicate_blocks(const uint8_t* ciphertext, size_t ciphertext_len) {

    // Enforce ct to be multiple of block size before continuing
    if (ciphertext_len % BLOCK_SIZE != 0) {
        return 0;
    }

    for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE) {
        for (size_t j = i + BLOCK_SIZE; j < ciphertext_len; j += BLOCK_SIZE) {
            if (memcmp(&ciphertext[i], &ciphertext[j], BLOCK_SIZE) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

int apply_pkcs7_padding(const uint8_t* prepad_pt, size_t prepad_pt_len, uint8_t** padded_pt, size_t* padded_pt_len) {

    // NULL checks
    if (!prepad_pt || !padded_pt_len) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    // Check block size is valid for padding to take place
    if (BLOCK_SIZE > UINT8_MAX) {
        return CRYPTOPALS_ERR_OUTOFBOUNDS;
    }

    size_t padding_count = (BLOCK_SIZE - (prepad_pt_len % BLOCK_SIZE));

    // Check for overflow before assignment
    if (prepad_pt_len > (SIZE_MAX - padding_count)) {
        fprintf(stderr, "ERROR: Overflow\n");
        return CRYPTOPALS_ERR_OVERFLOW;
    }
    *padded_pt_len = prepad_pt_len + padding_count; // Store the new length

    uint8_t padding_val = (uint8_t)padding_count;

    // Calloc memory for the new pt with padding
    *padded_pt = calloc(*padded_pt_len, sizeof(uint8_t));
    if (!*padded_pt) {
        return CRYPTOPALS_ERR_ALLOC_FAIL; // Failed calloc error
    }

    // Copy the existing contents of pt to the pt that will be padded
    memcpy(*padded_pt, prepad_pt, prepad_pt_len);

    // Pad it with the padding byte value worked out earlier
    for (size_t i = prepad_pt_len; i < *padded_pt_len; i++) {
        (*padded_pt)[i] = padding_val;
    }

    return CRYPTOPALS_SUCCESS;
}

int strip_pkcs7_padding(const uint8_t* padded_pt, size_t padded_pt_len, uint8_t** unpadded_pt, size_t* unpadded_pt_len) {

    // Check for length errors
    if (padded_pt_len == 0 || (padded_pt_len % BLOCK_SIZE) != 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Check for NULL
    if (!padded_pt) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    uint8_t final_byte = padded_pt[padded_pt_len - 1];
    if (final_byte == 0 || final_byte > BLOCK_SIZE || final_byte > padded_pt_len) {
        // Not valid padding, so leave the plaintext and its lengths untouched for the results
        *unpadded_pt_len = padded_pt_len;
    } else {
        // Valid padding, so update the length
        *unpadded_pt_len = padded_pt_len - final_byte;
    }

    // Allocate memory for unpadded plaintext
    *unpadded_pt = malloc(*unpadded_pt_len);
    if (!*unpadded_pt) {
        return CRYPTOPALS_ERR_ALLOC_FAIL; // Memory allocation failed
    }

    memcpy(*unpadded_pt, padded_pt, *unpadded_pt_len);

    return 0;
}

int check_and_strip_padding(const uint8_t* padded_pt, size_t padded_pt_len, uint8_t** unpadded_pt, size_t* unpadded_pt_len) {

    // Check for NULL
    if (!padded_pt) {
        return CRYPTOPALS_ERR_NULL_PTR;
    }

    // Check for length errors
    if (padded_pt_len == 0 || (padded_pt_len % BLOCK_SIZE) != 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    uint8_t final_byte = padded_pt[padded_pt_len - 1];

    if (final_byte == 0 || final_byte > BLOCK_SIZE) {
        return CRYPTOPALS_ERR_MISCELLANEOUS; // Throw error on bad padding like challenge wants
    }

    // Check that exactly i of the final bytes have the same value of the final byte
    for (uint8_t i = 0; i < final_byte; i++) {

        if (final_byte != padded_pt[padded_pt_len - 1 - i]) {
            return CRYPTOPALS_ERR_MISCELLANEOUS; // Bad padding
        }
    }

    // If passed all the above checks, it is good padding and can strip it
    if (strip_pkcs7_padding(padded_pt, padded_pt_len, unpadded_pt, unpadded_pt_len) != 0) {
        return CRYPTOPALS_ERR_MISCELLANEOUS; // Strip padding error
    }

    return 0;
}

int aes_ecb_encrypt(const uint8_t* plaintext, const size_t plaintext_len, const uint8_t* key, uint8_t** ciphertext, size_t* ciphertext_len) {

    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int ct_len = 0;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("ERROR: Context initialisation failed\n");
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    // Initialise encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        printf("ERROR: EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    // Calloc memory only if the size does not exceed size_t max value
    if (plaintext_len > (SIZE_MAX - AES_BLOCK_SIZE)) {
        printf("ERROR: More memory required than size_t allows for\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_OUTOFBOUNDS;
    }
    *ciphertext = calloc(plaintext_len + AES_BLOCK_SIZE, sizeof(uint8_t));
    if (*ciphertext == NULL) {
        printf("ERROR: Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    // EVP encrypt function takes length as 'int' - check size before cast
    if (plaintext_len > INT_MAX) {
        printf("ERROR: plaintext_len too large\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return CRYPTOPALS_ERR_OUTOFBOUNDS;
    }

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, (int)plaintext_len)) {
        printf("ERROR: EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return CRYPTOPALS_ERR_ENCRYPT;
    }
    ct_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        printf("ERROR: EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return CRYPTOPALS_ERR_ENCRYPT;
    }
    ct_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (ct_len < 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    *ciphertext_len = (size_t)ct_len;
    return 0;
}

int aes_ecb_decrypt(const uint8_t* ciphertext, const size_t ciphertext_len, const uint8_t* key, uint8_t** plaintext, size_t* plaintext_len) {

    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int pt_len = 0;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("ERROR: Context initialisation failed\n");
        return CRYPTOPALS_ERR_DECRYPT;
    }

    // Initialise decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        printf("ERROR: EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_DECRYPT;
    }

    // Disable padding
    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        printf("ERROR: Disabling padding failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_DECRYPT;
    }

    // Calloc memory only if the size does not exceed size_t max value
    if (ciphertext_len > (SIZE_MAX - AES_BLOCK_SIZE)) {
        printf("ERROR: More memory required than size_t allows for\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_LENGTH;
    }
    *plaintext = calloc(ciphertext_len + AES_BLOCK_SIZE, sizeof(uint8_t));
    if (*plaintext == NULL) {
        printf("ERROR: Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    // EVP decrypt function takes length as 'int' - check size before cast
    if (ciphertext_len > INT_MAX) {
        printf("ERROR: Ciphertext length is too large\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, (int)ciphertext_len)) {
        printf("ERROR: EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return CRYPTOPALS_ERR_DECRYPT;
    }
    pt_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        printf("ERROR: EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return CRYPTOPALS_ERR_DECRYPT;
    }
    pt_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (pt_len < 0) {
        return CRYPTOPALS_ERR_LENGTH;
    }

    *plaintext_len = (size_t)pt_len;
    return CRYPTOPALS_SUCCESS;
}

int aes_cbc_decrypt(const uint8_t* key, const uint8_t* ciphertext, const size_t ciphertext_len, const uint8_t* init_vec, uint8_t** plaintext,
                    size_t* plaintext_len) {

    // Calloc enough memory for the entire resulting plaintext (cannot be larger than ciphertext_len considering padding)
    *plaintext = calloc(ciphertext_len, sizeof(uint8_t));
    if (*plaintext == NULL) {
        printf("ERROR: Memory allocation failed\n");
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    // Set prev ciphertext to the values in init_vec
    uint8_t prev_ciphertext[AES_BLOCK_SIZE];
    memcpy(prev_ciphertext, init_vec, AES_BLOCK_SIZE);

    // Loop through in blocks of BLOCK SIZE
    for (size_t i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {

        uint8_t* decrypted_block = NULL;
        size_t decrypted_block_len;

        // ECB decrypt that block to get a plaintext block
        if (aes_ecb_decrypt(ciphertext + i, AES_BLOCK_SIZE, key, &decrypted_block, &decrypted_block_len) != 0) {
            printf("ERROR: ECB Decryption failed\n");
            free(decrypted_block); // Free if failed
            free(*plaintext);
            return CRYPTOPALS_ERR_DECRYPT;
        }

        uint8_t plaintext_block[AES_BLOCK_SIZE] = {0};

        if (xor_on_bytes(decrypted_block, prev_ciphertext, plaintext_block, AES_BLOCK_SIZE) != 0) {
            printf("ERROR: XOR failed\n");
            free(decrypted_block); // Free if failed
            free(*plaintext);
            return CRYPTOPALS_ERR_MISCELLANEOUS;
        }                                                        // XOR decrypted block with prev_ciphertext
        memcpy(*plaintext + i, plaintext_block, AES_BLOCK_SIZE); // Append the resulting pt block to the ongoing plaintext
        memcpy(prev_ciphertext, ciphertext + i, AES_BLOCK_SIZE); // Set prev_ciphertext to current ciphertext block

        free(decrypted_block); // Free before next loop iteration
    }

    // Strip padding
    uint8_t* unpadded_plaintext = NULL;
    size_t unpadded_plaintext_len = 0;

    if (strip_pkcs7_padding(*plaintext, ciphertext_len, &unpadded_plaintext, &unpadded_plaintext_len) != 0) {
        printf("ERROR: Strip padding failed\n");
        free(*plaintext);
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Set the plaintext and new pt lengths
    *plaintext_len = unpadded_plaintext_len;
    memcpy(*plaintext, unpadded_plaintext, unpadded_plaintext_len);

    free(unpadded_plaintext);

    return CRYPTOPALS_SUCCESS;
}

int aes_cbc_encrypt(const uint8_t* key, const uint8_t* plaintext, const size_t plaintext_len, const uint8_t* init_vec, uint8_t** ciphertext,
                    size_t* ciphertext_len) {

    uint8_t* padded_plaintext;
    size_t padded_plaintext_len;

    // Apply padding to plaintext
    if (apply_pkcs7_padding(plaintext, plaintext_len, &padded_plaintext, &padded_plaintext_len) != 0) {
        printf("ERROR: Padding error\n");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Calloc for ct result
    *ciphertext = calloc(padded_plaintext_len, sizeof(uint8_t));
    if (*ciphertext == NULL) {
        printf("ERROR: Memory allocation failed\n");
        free(padded_plaintext);
        return CRYPTOPALS_ERR_ALLOC_FAIL;
    }

    // Set prev ciphertext to init_vec
    uint8_t prev_ciphertext[AES_BLOCK_SIZE];
    memcpy(prev_ciphertext, init_vec, AES_BLOCK_SIZE);

    // Loop through in blocks of BLOCK SIZE
    for (size_t i = 0; i < padded_plaintext_len; i += AES_BLOCK_SIZE) {

        // Store the pt block being worked on
        uint8_t plaintext_block[AES_BLOCK_SIZE];
        memcpy(plaintext_block, padded_plaintext + i, AES_BLOCK_SIZE);

        // XOR plaintext block with prev_ciphertext block
        uint8_t xor_result[AES_BLOCK_SIZE];
        if (xor_on_bytes(prev_ciphertext, plaintext_block, xor_result, AES_BLOCK_SIZE) != 0) {
            printf("ERROR: XOR failed\n");
            free(padded_plaintext);
            free(*ciphertext);
            return CRYPTOPALS_ERR_ENCRYPT;
        }

        // ECB encrypt that xor result to get a ciphertext block
        uint8_t* encrypted_block = NULL;
        size_t encrypted_block_len = 0;
        if (aes_ecb_encrypt(xor_result, AES_BLOCK_SIZE, key, &encrypted_block, &encrypted_block_len) != 0) {
            printf("ERROR: AES ECB Encryption error\n");
            if (encrypted_block) {
                free(encrypted_block);
            }
            free(padded_plaintext);
            free(*ciphertext);
            return CRYPTOPALS_ERR_ENCRYPT;
        }

        // Append the resulting ct block to the ongoing ciphertext
        memcpy(*ciphertext + i, encrypted_block, AES_BLOCK_SIZE);

        // Set prev_ciphertext to current ciphertext block
        memcpy(prev_ciphertext, encrypted_block, AES_BLOCK_SIZE);

        // Free the encrypted block after using it
        free(encrypted_block);
    }

    // Set the ciphertext and new ct lengths
    *ciphertext_len = padded_plaintext_len;

    free(padded_plaintext);

    return CRYPTOPALS_SUCCESS;
}

int generate_random_key(uint8_t* key, size_t key_len) {
    if (key_len > (UINT8_MAX + 1)) { // Cannot be more than 256 for use of the getentropy function
        printf("ERROR: Key size too large\n");
        return CRYPTOPALS_ERR_OUTOFBOUNDS;
    }

    if (getentropy(key, key_len) == -1) {
        printf("ERROR: Entropy failure\n");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    return CRYPTOPALS_SUCCESS;
}
