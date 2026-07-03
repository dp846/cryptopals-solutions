import pytest
from src.task09 import apply_pkcs7_padding, strip_pkcs7_padding

def test_apply_pkcs7_padding_valid():
    original_bytes = b"YELLOW SUBMARINE"
    block_size = 20

    padded_bytes = apply_pkcs7_padding(original_bytes, block_size)

    assert len(padded_bytes) % block_size == 0, "Padded data should be a multiple of block size"
    assert padded_bytes.endswith(b'\x04' * 4), "Padding byte should match the number of padded bytes"

def test_apply_pkcs7_padding_same_size():
    original_bytes = b"YELLOW SUBMARINEEEEE"
    block_size = 20

    padded_bytes = apply_pkcs7_padding(original_bytes, block_size)
    assert len(padded_bytes) % block_size == 0, "Padded data should be a multiple of block size"

def test_strip_pkcs7_padding_valid():
    original_bytes = b"YELLOW SUBMARINE"
    padded_bytes = b"YELLOW SUBMARINE" + b'\x04' * 4
    stripped_bytes = strip_pkcs7_padding(padded_bytes)
    assert stripped_bytes == original_bytes, "Stripped data should match the original data"