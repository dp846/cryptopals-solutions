// ECB cut-and-paste

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

#include "byte_utils.h"
#include "crypto_utils.h"
#include "error_codes.h"
#include "file_utils.h"
#include "zero_memory.h"

#define NUM_PAIRS 3
#define BLOCK_SIZE 16
#define MAX_BUFFER_SIZE 4096

uint8_t KEY[BLOCK_SIZE];

typedef struct {
    char* key;
    char* value;
} KEY_VAL_PAIR;

/*Parses a bytes buffer into a profile array, of KEY_VAL_PAIR structs*/
int kv_parser(const uint8_t* encoded_profile, const size_t encoded_len, KEY_VAL_PAIR* profile) {

    // Check for NULL
    if (!encoded_profile || !profile) {
        return CRYPTOPALS_FAIL_N;
    }

    // Duplicate the profile string to manipulate
    char* profile_str = strndup((const char*)encoded_profile, encoded_len);
    if (!profile_str) {
        return CRYPTOPALS_FAIL_N;
    }

    char* saveptr;
    char* tkn = strtok_r(profile_str, "&", &saveptr);

    int i = 0;
    while (tkn) {
        char* equal_pos = strchr(tkn, '=');
        if (equal_pos) {
            *equal_pos = '\0';

            // Duplicate key and check for failure
            profile[i].key = strdup(tkn);
            if (!profile[i].key) {
                printf("ERROR: Key memory allocation failed\n");

                // Free all
                for (int j = 0; j < i; ++j) {
                    free(profile[j].key);
                    free(profile[j].value);
                }
                free(profile_str);

                return CRYPTOPALS_FAIL_N;
            }

            // Duplicate value and check for failure
            profile[i].value = strdup(equal_pos + 1);
            if (!profile[i].value) {
                printf("ERROR: Value memory allocation failed\n");

                // Free all
                free(profile[i].key);
                for (int j = 0; j < i; ++j) {
                    free(profile[j].key);
                    free(profile[j].value);
                }
                free(profile_str);

                return CRYPTOPALS_FAIL_N;
            }

            i++;
        } else { // Did not find an = symbol
            printf("ERROR: Invalid k=v format - no equals found\n");

            // Free all
            for (int j = 0; j < i; ++j) {
                free(profile[j].key);
                free(profile[j].value);
            }
            free(profile_str);

            return CRYPTOPALS_FAIL_N;
        }

        tkn = strtok_r(NULL, "&", &saveptr);
    }

    free(profile_str);
    return i; // Return the number of pairs found
}

/*Encodes an array of KEY_VAL_PAIR structs into a bytes array for the profile*/
int encode_profile(const KEY_VAL_PAIR* profile, uint8_t* encoded_profile, size_t encoded_profile_len) {

    // Copy each into an array
    size_t cur_pos = 0;
    for (size_t i = 0; i < NUM_PAIRS; i++) {
        size_t key_len = strlen(profile[i].key);
        size_t value_len = strlen(profile[i].value);

        // Check for wrapping before addition operations take place
        if (cur_pos > (SIZE_MAX - key_len) || cur_pos > (SIZE_MAX - value_len)) {
            printf("ERROR: Wrapping size_t\n");
            return CRYPTOPALS_ERR_WRAPPING;
        }

        // Check if an overflow will occur or not before performing the copy operation for the key and the '='
        if (cur_pos + key_len + 1 > encoded_profile_len) {
            return CRYPTOPALS_ERR_OVERFLOW;
        }
        memcpy((char*)encoded_profile + cur_pos, profile[i].key, key_len);
        cur_pos += key_len;

        *((char*)encoded_profile + cur_pos) = '='; // Insert =
        cur_pos += 1;

        // Check if an overflow will occur or not before performing the copy operation for value
        if (cur_pos + value_len > encoded_profile_len) {
            return CRYPTOPALS_ERR_OVERFLOW;
        }
        memcpy((char*)encoded_profile + cur_pos, profile[i].value, value_len);
        cur_pos += value_len;

        if (i < NUM_PAIRS - 1) {
            if (cur_pos + 1 >= encoded_profile_len) { // Check that inserting the & is doable
                return CRYPTOPALS_ERR_OVERFLOW;
            }
            *((char*)encoded_profile + cur_pos) = '&'; // Insert &
            cur_pos += 1;
        }
    }

    // Ensure null termination
    if (cur_pos < encoded_profile_len) {
        encoded_profile[cur_pos] = '\0';
    } else {
        encoded_profile[encoded_profile_len - 1] = '\0';
    }

    return CRYPTOPALS_SUCCESS;
}

/*Takes an email string, removes the possible parsing characters, then creates an encrypted profile*/
int profile_for(char* email, uint8_t** encrypted_profile, size_t* encrypted_len) {

    // Make an array of 3 kv structs
    KEY_VAL_PAIR profile[3];

    // This is to ensure that the non-const pointers in my KEY_VAL struct point to mutable memory
    char key_email[] = "email";
    char key_uid[] = "uid";
    char key_role[] = "role";
    char value_10[] = "10";
    char value_user[] = "user";
    profile[0].key = key_email;
    profile[0].value = email;
    profile[1].key = key_uid;
    profile[1].value = value_10;
    profile[2].key = key_role;
    profile[2].value = value_user;

    // Work out the length of all the key values combined
    size_t profile_len = 0;
    for (size_t i = 0; i < NUM_PAIRS; i++) {

        // Check for wrapping
        if (strlen(profile[i].key) > (SIZE_MAX - strlen(profile[i].value)) ||
            profile_len > (SIZE_MAX - strlen(profile[i].key) - strlen(profile[i].value) - 1)) {
            printf("ERROR: Overflow\n");
            return CRYPTOPALS_ERR_OVERFLOW;
        }

        profile_len += strlen(profile[i].key);
        profile_len += 1; // For the =
        profile_len += strlen(profile[i].value);
    }
    profile_len += (NUM_PAIRS - 1); // For the &s

    // Check for out of range VLA length
    if (profile_len == 0 || profile_len > MAX_BUFFER_SIZE) {
        printf("ERROR: Invlaid range for array length\n");
        return CRYPTOPALS_ERR_LENGTH;
    }

    uint8_t encoded_profile[profile_len];

    // Encode the profile
    if (encode_profile(profile, encoded_profile, profile_len) != 0) {
        printf("ERROR: Encode profile failed\n");
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    uint8_t* padded_profile = NULL;
    size_t padded_len = 0;

    // Apply padding
    if (apply_pkcs7_padding(encoded_profile, profile_len, &padded_profile, &padded_len) != 0) {
        printf("ERROR: Padding error\n");
        free(padded_profile);
        return CRYPTOPALS_ERR_MISCELLANEOUS;
    }

    // Encrypt profile
    if (aes_ecb_encrypt(padded_profile, padded_len, KEY, encrypted_profile, encrypted_len) != 0) {
        printf("ERROR: Encryption error\n");
        free(padded_profile);
        return CRYPTOPALS_ERR_ENCRYPT;
    }

    free(padded_profile);

    return CRYPTOPALS_SUCCESS;
}

int main(void) {

    int ret = CRYPTOPALS_SUCCESS;

    // Generate a random unknown key in a variable to use repeatedly
    if (generate_random_key(KEY, BLOCK_SIZE) != 0) {
        printf("ERROR: Key generation fail\n");
        return CRYPTOPALS_FAIL;
    }

    const char pad = 11; // As admin is 5 in length, padding should make it a full block

    // A - Second email (Admin) - ensures that a block is in the format of
    // 'admin' + padding (assuming block size is 16 here)
    char email_A[] = {'f', 'o', 'o', '@', 'b', 'a', 'r', 'r', 'r', 'r', 'a', 'd', 'm', 'i', 'n', pad,
                      pad, pad, pad, pad, pad, pad, pad, pad, pad, pad, '.', 'c', 'o', 'm', '\0'};

    // NA - First email (No Admin) - ensures that a block ends with 'role='
    char email_NA[] = "foo@barrr.com";

    // Initialising for profile ciphertext generation
    uint8_t* ct_NA = NULL;
    size_t ct_NA_len = 0;
    uint8_t* ct_A = NULL;
    size_t ct_A_len = 0;

    // Initialising for crafted admin profile
    size_t encrypted_admin_len = 3 * (size_t)BLOCK_SIZE; // The layout will take up 3 blocks - 2 from NA, one from A
    uint8_t encrypted_admin[encrypted_admin_len];

    // Initialising for decryption and stripping
    uint8_t* decrypted_admin = NULL;
    size_t decrypted_admin_len = 0;
    uint8_t* stripped_decrypted = NULL;
    size_t stripped_decrypted_len = 0;

    KEY_VAL_PAIR profile[NUM_PAIRS];

    // Encrypted profile generations
    if (profile_for(email_NA, &ct_NA, &ct_NA_len) != 0) {
        printf("ERROR: Failed to make the first profile\n");
        ret = CRYPTOPALS_FAIL;
        goto err_profile_NA;
    }
    if (profile_for(email_A, &ct_A, &ct_A_len) != 0) {
        printf("ERROR: Failed to make the second profile\n");
        ret = CRYPTOPALS_FAIL;
        goto err_profile_A;
    }

    // Copy blocks 1 and 2 from NA, and then block 2 from A onto the end
    memcpy(encrypted_admin, ct_NA, (ptrdiff_t)BLOCK_SIZE * 2);
    memcpy(encrypted_admin + ((ptrdiff_t)BLOCK_SIZE * 2), ct_A + (ptrdiff_t)BLOCK_SIZE, (ptrdiff_t)BLOCK_SIZE);

    printf("Encrypted admin profile: ");
    print_bytes(encrypted_admin, encrypted_admin_len);

    // Decrypt the encrypted profile to show it has role=admin
    if (aes_ecb_decrypt(encrypted_admin, encrypted_admin_len, KEY, &decrypted_admin, &decrypted_admin_len) != 0) {
        printf("ERROR: Decryption failed\n");
        ret = CRYPTOPALS_FAIL;
        goto err_decrypt;
    }

    // Strip padding
    if (strip_pkcs7_padding(decrypted_admin, decrypted_admin_len, &stripped_decrypted, &stripped_decrypted_len) != 0) {
        printf("ERROR: Strip padding error\n");
        ret = CRYPTOPALS_FAIL;
        goto err_strip_padding;
    }

    // Parse the profile
    if (kv_parser(stripped_decrypted, stripped_decrypted_len, profile) != NUM_PAIRS) {
        printf("ERROR: Parsing failed - %d pairs expected\n", NUM_PAIRS);
        ret = CRYPTOPALS_FAIL;
        goto err_parse;
    }

    // Output the generated profile with admin
    printf("\nGenerated a cookie with an admin role:\n");
    printf("{\n");
    for (int i = 0; i < NUM_PAIRS; ++i) {
        printf("    %s: %s\n", profile[i].key, profile[i].value);
    }
    printf("}\n");

    // Cleanup
    for (int i = 0; i < NUM_PAIRS; ++i) {
        free(profile[i].key);
        free(profile[i].value);
    }

err_parse:
err_strip_padding:
    free(stripped_decrypted);
err_decrypt:
    free(decrypted_admin);
err_profile_A:
    if (ct_A) {
        free(ct_A);
    }
err_profile_NA:
    if (ct_NA) {
        free(ct_NA);
    }

// Zero out the key in memory after use
#ifdef USE_LIBSODIUM
    sodium_memzero(KEY, BLOCK_SIZE);
#else
    zero_memory(KEY, BLOCK_SIZE, BLOCK_SIZE);
#endif

    return ret;
}
