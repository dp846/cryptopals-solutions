import pytest
from src.task10 import aes_cbc_encryption, aes_cbc_decryption

def test_aes_cbc_encryption_decryption():
    key = b"YELLOW SUBMARINE"
    iv = b"0" * 16
    plaintext = b"Hello World"

    # Encrypt the plaintext
    encrypted_text = aes_cbc_encryption(plaintext, key, iv)

    # Decrypt the encrypted text
    decrypted_text = aes_cbc_decryption(encrypted_text, key, iv)

    # Check if decrypted text is the same as original plaintext
    assert decrypted_text == plaintext, f"Decrypted text {decrypted_text} is not the same as original plaintext"