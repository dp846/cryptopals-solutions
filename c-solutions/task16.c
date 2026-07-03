// CBC bitflipping attacks

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

uint8_t KEY[BLOCK_SIZE];
uint8_t INIT_VEC[BLOCK_SIZE];

/*Prepends and appends strings to a user's input and encrypts it with CBC mode*/
int aes_cbc_prepend_and_encrypt(const uint8_t* input, const size_t input_len, uint8_t** ciphertext, size_t* ciphertext_len) {

    const char* str_1 = "comment1=cooking%20MCs;userdata=";
    const char* str_2 = ";comment2=%20like%20a%20pound%20of%20bacon";

    const size_t str_1_len = strlen(str_1);
    const size_t str_2_len = strlen(str_2);

    // Check for wrapping
    if (str_1_len > SIZE_MAX - str_2_len || input_len > SIZE_MAX - str_1_len - str_2_len) {
        printf("ERROR: Overflow\n");
        return CRYPTOPALS_ERR_WRAPPING;
    }

    size_t plaintext_len = str_1_len + input_len + str_2_len;

    // Check for invalid VLA length
    if (plaintext_len > MAX_BUFFER_SIZE || plaintext_len == 0) {
        printf("ERROR: VLA length not in valid range\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    char plaintext[plaintext_len + 1];
    memset(plaintext, 0, sizeof(plaintext));

    size_t index = 0;

    // Copy over the first string
    memcpy(plaintext, str_1, str_1_len);

    // Check for wrapping before addition
    if (index > SIZE_MAX - str_1_len) {
        printf("ERROR: Overflow\n");
        return CRYPTOPALS_ERR_OVERFLOW;
    }
    index += str_1_len;

    // Quote out and copy over the input
    for (size_t i = 0; i < input_len; i++) {

        // Check for wrapping before next loop increment
        if (index == SIZE_MAX) {
            printf("ERROR: Overflow\n");
            return CRYPTOPALS_ERR_OVERFLOW;
        }

        if (input[i] != ';' && input[i] != '=') {
            plaintext[index++] = input[i];
        } else {
            plaintext[index++] = '_';
        }
    }

    // Append the last string
    memcpy(plaintext + index, str_2, str_2_len);

    // Check for wrapping before final addition
    if (index > SIZE_MAX - str_2_len) {
        printf("ERROR: Overflow\n");
        return CRYPTOPALS_ERR_OVERFLOW;
    }
    index += str_2_len;

    plaintext[index] = '\0';

    printf("\nThe appended plaintext: %s\n", plaintext);

    // Encrypt the full built plaintext
    if (aes_cbc_encrypt(KEY, (uint8_t*)plaintext, plaintext_len, INIT_VEC, ciphertext, ciphertext_len) != 0) {
        printf("ERROR: CBC encryption failed\n");
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    return CRYPTOPALS_SUCCESS;
}

/**
 * Decrypts a given ciphertext and looks for an admin flag substring in the plaintext
 *
 * @returns 1 for true, 0 for false, -1 for error
 */
int check_for_admin(const uint8_t* ciphertext, const size_t ciphertext_len, uint8_t** plaintext, size_t* plaintext_len) {

    // Decrypt ciphertext
    if (aes_cbc_decrypt(KEY, ciphertext, ciphertext_len, INIT_VEC, plaintext, plaintext_len) != 0) {
        printf("ERROR: CBC decryption failed\n");
        return -1;
    }

    // Ouput decrypted
    printf("\nDecrypted plaintext:\n");
    for (size_t i = 0; i < *plaintext_len; i++) {
        if (isprint((*plaintext)[i])) {
            printf("%c", (*plaintext)[i]);
        }
    }
    printf("\n");

    const char admin_str[] = ";admin=true;";
    const size_t admin_str_len = strlen(admin_str);

    // Check if length subtraction operation will wrap below 0
    if (*plaintext_len < admin_str_len) {
        printf("ERROR: Operation on size_t will wrap\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    // Check for the admin string within the plaintext
    for (size_t i = 0; i < (*plaintext_len - admin_str_len); i++) {
        if (memcmp(*plaintext + i, admin_str, admin_str_len) == 0) {
            return 1; // For true
        }
    }

    return 0; // For false
}

int main(void) {

    int ret = 0;

    // Initialising variables for use

    const uint8_t nulling_mask[] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'};

    uint8_t admin_mask[] = {'X', 'X', 'X', 'X', 'X', ';', 'a', 'd', 'm', 'i', 'n', '=', 't', 'r', 'u', 'e'};

    const uint8_t input[] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                             'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'};

    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;

    uint8_t third_ct_block[BLOCK_SIZE];
    memset(third_ct_block, 0, BLOCK_SIZE);

    uint8_t xor_result_1[BLOCK_SIZE];
    memset(xor_result_1, 0, BLOCK_SIZE);
    uint8_t xor_result_2[BLOCK_SIZE];
    memset(xor_result_2, 0, BLOCK_SIZE);

    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;

    // Generate a random (consistent) key for use across multiple oracle calls
    if (getentropy(KEY, BLOCK_SIZE) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        ret = CRYPTOPALS_FAIL;
        goto err_key_gen;
    }

    // Generate a random (consistent) IV for use across multiple oracle calls
    if (getentropy(INIT_VEC, BLOCK_SIZE) == -1) {
        printf("ERROR: Unable to generate random numbers\n");
        ret = CRYPTOPALS_FAIL;
        goto err_iv_gen;
    }

    printf("Random 16 byte key: ");
    print_bytes(KEY, BLOCK_SIZE);

    printf("Random 16 byte IV: ");
    print_bytes(INIT_VEC, BLOCK_SIZE);

    // Use the prepend and encrypt function
    if (aes_cbc_prepend_and_encrypt(input, (2 * BLOCK_SIZE), &ciphertext, &ciphertext_len) != 0) {
        printf("ERROR: Failed to prepend and encrypt\n");
        ret = CRYPTOPALS_FAIL;
        goto err_encrypt;
    }

    // Output the resulting encrypted bytes
    printf("\nThe ciphertext result: ");
    print_bytes(ciphertext, ciphertext_len);
    printf("\n\n");

    // ----- ATTACK ------ //

    printf("Performing the attack...\n");

    // XOR the null mask with admin flag block
    if (xor_on_bytes(nulling_mask, admin_mask, xor_result_1, BLOCK_SIZE) != 0) {
        printf("ERROR: XOR Failure\n");
        ret = CRYPTOPALS_FAIL;
        goto err_xor_1;
    }

    // Store the 3rd ct block for use
    memcpy(third_ct_block, ciphertext + (2 * BLOCK_SIZE), BLOCK_SIZE);

    // XOR that last xor result with the 3rd ct block
    if (xor_on_bytes(xor_result_1, third_ct_block, xor_result_2, BLOCK_SIZE) != 0) {
        printf("ERROR: XOR Failure\n");
        ret = CRYPTOPALS_FAIL;
        goto err_xor_2;
    }

    // Insert it back into the 3rd block position of the ciphertext
    memcpy(ciphertext + (2 * BLOCK_SIZE), xor_result_2, BLOCK_SIZE);

    // Now check for the admin
    if (check_for_admin(ciphertext, ciphertext_len, &plaintext, &plaintext_len) == 1) {
        printf("\nPASS: Admin flag detected\n");
        ret = CRYPTOPALS_SUCCESS;
        goto pass_admin_flag;
    } else {
        printf("\nFAIL: Admin flag not detected\n");
        ret = CRYPTOPALS_FAIL;
        goto err_admin_flag;
    }

err_admin_flag:
pass_admin_flag:
    free(plaintext);
err_xor_2:
err_xor_1:
err_encrypt:
    free(ciphertext);
err_iv_gen:

    // Remove IV from memory
#ifdef USE_LIBSODIUM
    sodium_memzero(INIT_VEC, BLOCK_SIZE);
#else
    zero_memory(INIT_VEC, BLOCK_SIZE, BLOCK_SIZE);
#endif

err_key_gen:

    // Remove KEY from memory
#ifdef USE_LIBSODIUM
    sodium_memzero(KEY, BLOCK_SIZE);
#else
    zero_memory(KEY, BLOCK_SIZE, BLOCK_SIZE);
#endif

    return ret;
}
