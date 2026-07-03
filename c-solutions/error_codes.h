#ifndef CRYPTOPALS_ERROR_CODES_H
#define CRYPTOPALS_ERROR_CODES_H

// Error codes for use in the Cryptopals challenges

#define CRYPTOPALS_FAIL_N (-1) // Negative failure for certain functions
#define CRYPTOPALS_SUCCESS 0   // Succes both in main() and all other functions
#define CRYPTOPALS_FAIL 1      // A fail in main() will return 1

// Other error codes for functions other than main():
#define CRYPTOPALS_ERR_NULL_PTR 2
#define CRYPTOPALS_ERR_ALLOC_FAIL 3
#define CRYPTOPALS_ERR_LENGTH 4
#define CRYPTOPALS_ERR_OUTOFBOUNDS 5
#define CRYPTOPALS_ERR_OVERFLOW 6
#define CRYPTOPALS_ERR_ENCRYPT 7
#define CRYPTOPALS_ERR_DECRYPT 8
#define CRYPTOPALS_ERR_MISCELLANEOUS 9
#define CRYPTOPALS_ERR_FILE_CLOSE 10
#define CRYPTOPALS_ERR_FILE_OPEN 11
#define CRYPTOPALS_ERR_WRAPPING 12

#endif
