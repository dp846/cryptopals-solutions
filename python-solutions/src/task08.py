## Detect AES in ECB mode

import os
from src.task04 import read_file_into_lines

def has_duplicates(ciphertext_blocks):
    """Simple function to check if a list of ciphertext blocks has any duplicates."""

    return len(ciphertext_blocks) != len(set(ciphertext_blocks))

def find_duplicate_blocks(ciphertext_bytes, BLOCK_SIZE=16):
    """Will scan a file of hex to check for duplicate blocks - used for detecting the use of ECB as it is deterministic."""

    ciphertext_blocks = [ciphertext_bytes[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext_bytes), BLOCK_SIZE)]
    return (has_duplicates(ciphertext_blocks))

if __name__ == '__main__':
    print(f"\nExecuting challenge 8 of cryptopals. Challenge detecting ECB mode for AES\n")

    FILE_NAME = os.path.join(os.path.dirname(__file__), "task08.txt")
    lines = read_file_into_lines(FILE_NAME)
    bytes_file_data = [bytes.fromhex(line) for line in lines]

    for line_number, ciphertext_line in enumerate(bytes_file_data, start=1):
        if find_duplicate_blocks(ciphertext_line):
            print(f'Duplicates found on line {line_number} of file "{FILE_NAME}". This means that ECB mode must have been used to encrypt. ')
        
    # This is what I found:
    line = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    repeated_part = "08649af70dc06f4fd5d2d69c744cd283"