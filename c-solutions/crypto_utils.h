#ifndef CRYPTO_UTILS
#define CRYPTO_UTILS

#include <stddef.h>
#include <stdint.h>

/**
 * Will perform an XOR operation byte by byte on two buffers of bytes
 *
 * @param buffer1 pointer to a bytes buffer
 * @param buffer2 pointer to a bytes buffer
 * @param result_buffer pointer to a bytes buffer to store the xor result
 * @param length size of the buffers to xor
 * NOTE: function assumes equal length buffers
 *
 * @returns 0 on success, non-zero error code for failure
 */
int xor_on_bytes(const uint8_t* buffer1, const uint8_t* buffer2, uint8_t* result_buffer, size_t length);

/**
 * Will extend a given key to the given extended key length by repeating the origianl key.
 *
 * @param key uint8 pointer to an array containing the key to repeat
 * @param key_len size of the key to repeat
 * @param extended_len size that the key will be extended to
 *
 * @returns a pointer to a created uint8_t array for the new extended key. Returns NULL pointer if an error occurs
 */
uint8_t* extend_key_repeated(const uint8_t* key, const size_t key_len, size_t extended_len);

/**
 * Scores a given stream of input data using frequency analysis of alphabetical characters
 *
 * @param data a uint8_t pointer to bytes input data to score
 * @param length the length of the data in bytes
 *
 * @returns double as the score value
 */
double score_text(uint8_t* data, size_t length);

/**
 * Finds the most likely plaintext of single byte XOR decryption given the ciphertext using frequency analysis
 *
 * @param ciphertext an array of bytes of the ciphertext
 * @param ciphertext_length size_t length of the ciphertext given
 * @param best_key_byte pointer to the byte that will store the best key
 *
 * @returns an array filled with the most likely plaintext message
 */
uint8_t* single_byte_xor_decryption(uint8_t* ciphertext, size_t ciphertext_length, uint8_t* best_key_byte);

/**
 * Looks for duplicate blocks within a ciphertext, used for detecting the use of ECB.
 * @note Assumes ciphertext length is a multiple of BLOCK_SIZE being used
 *
 * @param ciphertext array of ciphertext bytes
 * @param ciphertext_len length of ciphertext array
 *
 * @returns 0 for false (not found), 1 for true (found)
 */
int find_duplicate_blocks(const uint8_t* ciphertext, size_t ciphertext_len);

/**
 * Applies PKCS7 padding to given bytes of plaintext according to a BLOCK_SIZE
 *
 * @param prepad_pt array of plaintext bytes that will be padded
 * @param prepad_pt_len size of the plaintext bytes array BEFORE padding
 * @param padded_pt resulting array of plaintext bytes after padding has been applied
 * @param padded_pt_len resulting size of the array of plaintext bytes array AFTER padding
 *
 * @returns 0 for succes, non-zero error code for failure
 */
int apply_pkcs7_padding(const uint8_t* prepad_pt, size_t prepad_pt_len, uint8_t** padded_pt, size_t* padded_pt_len);

/**
 * Strips PKCS7 padding from padded plaintext if it is valid padding
 *
 * @param padded_pt plaintext bytes array with padding
 * @param padded_pt_len length of the padded plaintext
 * @param padded_pt resulting plaintext after stripping the padding
 * @param padded_pt resulting plaintext length after stripping the padding
 *
 * @returns 0 for success, non-zero error code for failure
 */
int strip_pkcs7_padding(const uint8_t* padded_pt, size_t padded_pt_len, uint8_t** unpadded_pt, size_t* unpadded_pt_len);

/**
 * Checks plaintext for valid padding. Will throw errors for bad padding, and strip valid padding.
 *
 * @param padded_pt plaintext bytes array with padding
 * @param padded_pt_len length of the padded plaintext
 * @param padded_pt resulting plaintext after stripping the padding
 * @param padded_pt resulting plaintext length after stripping the padding
 *
 * @returns 0 for success, non-zero error code for failure
 */
int check_and_strip_padding(const uint8_t* padded_pt, size_t padded_pt_len, uint8_t** unpadded_pt, size_t* unpadded_pt_len);

/**
 * Encrypt using AES-128 in ECB mode (using OpenSSL 1.1.1 - EVP_EncryptInit_ex is used)
 *
 * @param plaintext array of plaintext bytes to encrypt
 * @param plaintext_len size_t length of the plaintext array
 * @param key array of the key's bytes
 * @param ciphertext pointer to an array of bytes to store resulting ciphertext
 * @param ciphertext_len pointer to a size_t that will store the length of the resulting ciphertext
 *
 * @returns 0 for success, non-zero error code for failure
 */
int aes_ecb_encrypt(const uint8_t* plaintext, const size_t plaintext_len, const uint8_t* key, uint8_t** ciphertext, size_t* ciphertext_len);

/**
 * Decrypt using AES-128 in ECB mode (using OpenSSL 1.1.1 - EVP_EncryptInit_ex is used)
 *
 * @param ciphertext array of ciphertext bytes to decrypt
 * @param ciphertext_len size_t length of the ciphertext array
 * @param key array of the key's bytes
 * @param plaintext pointer to an array of bytes to store resulting plaintext
 * @param plaintext_len pointer to a size_t that will store the length of the resulting plaintext
 *
 * @returns 0 for success, non-zero error code for failure
 */
int aes_ecb_decrypt(const uint8_t* ciphertext, const size_t ciphertext_len, const uint8_t* key, uint8_t** plaintext, size_t* plaintext_len);

/**
 * Decrypts CBC encrypted ciphertext to give a resulting plaintext by chaining the use of ECB
 *
 * @param key aray of bytes for the key
 * @param ciphertext array of ciphertext bytes
 * @param ciphertext_len length of array of ciphertext bytes
 * @param init_vec aray of bytes for IV
 * @param plaintext array of plaintext bytes
 * @param plaintext_len length of array of plaintext bytes
 *
 * @returns 0 for success, non-zero error code for failure
 */
int aes_cbc_decrypt(const uint8_t* key, const uint8_t* ciphertext, const size_t ciphertext_len, const uint8_t* init_vec, uint8_t** plaintext,
                    size_t* plaintext_len);

/**
 * Encrypts plaintext with AES in CBC mode to give a resulting ciphertext by chaining the use of ECB
 *
 * @param key aray of bytes for the key
 * @param plaintext array of plaintext bytes
 * @param plaintext_len length of array of plaintext bytes
 * @param init_vec aray of bytes for IV
 * @param ciphertext array of ciphertext bytes
 * @param ciphertext_len length of array of ciphertext bytes
 *
 * @returns 0 for success, non-zero error code for failure
 */
int aes_cbc_encrypt(const uint8_t* key, const uint8_t* plaintext, const size_t plaintext_len, const uint8_t* init_vec, uint8_t** ciphertext,
                    size_t* ciphertext_len);

/**
 * Generates a key for encryption using getentropy
 *
 * @param key pointer to array of bytes that will be filled with key result
 * @param key_len length of the array for the key
 *
 * @returns 0 for success, non-zero error code for failure
 */
int generate_random_key(uint8_t* key, size_t key_len);

#endif
