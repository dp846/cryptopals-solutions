from src.task01 import hex_to_b64, b64_to_hex
import pytest

def test_hex_to_b64_valid():
    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert b64_str == hex_to_b64(hex_str)

def test_b64_to_hex_valid():
    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex_str == b64_to_hex(b64_str)

def test_invalid_base64():
    with pytest.raises(ValueError):
        b64_to_hex("invalid_base64")

def test_odd_length_hex():
    with pytest.raises(ValueError):
        hex_to_b64("123")

def test_empty_string():
    assert hex_to_b64("") == ""
    assert b64_to_hex("") == ""

def test_inversion():
    hex_str = "0a0a0a"
    assert b64_to_hex(hex_to_b64(hex_str)) == hex_str

    b64_str = "01234567"
    assert hex_to_b64(b64_to_hex(b64_str)) == b64_str