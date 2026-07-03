import pytest
from src.task11 import encryption_mode_detector, encryption_oracle

def test_ecb_cbc_oracle_detection():
    plaintext_bytes = b'Hello' * 100

    for _ in range(10):
        used_mode, ciphertext_bytes = encryption_oracle(plaintext_bytes)
        detected_mode = encryption_mode_detector(ciphertext_bytes)
        assert(detected_mode == used_mode), f"\nUsed mode {used_mode} for encryption, oracle detected mode {detected_mode}"