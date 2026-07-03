## An ECB/CBC detection oracle

import random
from src.task10 import aes_cbc_encryption, aes_ecb_encryption

def generate_random_key(key_length=16):
    """Generate a key of a given length of bytes (default length is 16)"""
    return bytes([random.randint(0, 255) for _ in range(key_length)])

def pad_plaintext_randomly(plaintext_bytes, min=5, max=10):
    """Generate a key of a given length of bytes (default length is 16)"""
    num_bytes_before, num_bytes_after = random.randint(min, max), random.randint(min, max)
    bytes_before = bytes([random.randint(0, 255) for _ in range(num_bytes_before)]) 
    bytes_after = bytes([random.randint(0, 255) for _ in range(num_bytes_after)])
    return bytes_before + plaintext_bytes + bytes_after

def encryption_oracle(plaintext_bytes):
    """
    Given input plaintext bytes, will append 5-10 bytes before and after the plaintext before choosing between ECB and CBC randomly to encrypt.
    Will return both the mode (only for checks later) and the resulting ciphertext for the detector function
    """
    # Generate a random key
    rand_key = generate_random_key()
    rand_IV = generate_random_key() #IV same size as key here

    # Pad by a random amount either end of the plaintext
    padded_plaintext = pad_plaintext_randomly(plaintext_bytes)

    # Encrypt using this random key using either CBC or ECB
    choice_of_cipher = random.randint(1,2)
    if choice_of_cipher == 1:
        # ECB
        ciphertext_result = aes_ecb_encryption(padded_plaintext, rand_key)
        return "ECB", ciphertext_result
    else:
        #CBC
        ciphertext_result = aes_cbc_encryption(padded_plaintext, rand_key, rand_IV)
        return "CBC", ciphertext_result

def encryption_mode_detector(ciphertext_bytes, BLOCK_SIZE=16):
    """Detect the mode of encryption based on the logic of earlier task - ECB produces duplicate blocks eventually"""

    ciphertext_blocks = [ciphertext_bytes[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext_bytes), BLOCK_SIZE)]
    
    if len(ciphertext_blocks) != len(set(ciphertext_blocks)):
        return "ECB"
    else:
        return "CBC"


if __name__ == '__main__':
    print(f"\nExecuting challenge 11 of cryptopals. Challenge involves a CBC and ECB mode oracle\n")

    plaintext_bytes = b'Hello world, I am super cool' * 100

    for i in range(1, 11):
        used_mode, ciphertext_bytes = encryption_oracle(plaintext_bytes)
        detected_mode = encryption_mode_detector(ciphertext_bytes)
        print(f"{i}) Used mode {used_mode} for encryption, oracle detected mode {detected_mode}\n")
        assert(detected_mode == used_mode)
