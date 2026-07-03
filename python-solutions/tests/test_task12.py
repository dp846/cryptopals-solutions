import pytest
from src.task12 import byte_by_byte_ecb_decryption, aes_128_ecb_encryption_oracle
from src.task11 import generate_random_key
from base64 import b64decode

def test_byte_by_byte_ecb_decryption():

    # Sets up the unknown message
    UNKNOWN_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    UNKNOWN_BYTES = b64decode(UNKNOWN_B64)
    RANDOM_KEY = generate_random_key()
    # Testing that the byte-by-byte decryption function correctly decrypts the UNKNOWN_BYTES
    block_size = 16
    decrypted_message = byte_by_byte_ecb_decryption(aes_128_ecb_encryption_oracle, RANDOM_KEY, block_size, len(UNKNOWN_BYTES))
    assert decrypted_message == UNKNOWN_BYTES