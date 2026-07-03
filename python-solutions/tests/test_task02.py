import pytest
from src.task02 import xor_combination_hex

def test_xor_combination_valid():
    hex_str1 = "1c0111001f010100061a024b53535009181c"
    hex_str2 = "686974207468652062756c6c277320657965"
    expected_output = "746865206b696420646f6e277420706c6179"
    
    assert xor_combination_hex(hex_str1, hex_str2) == expected_output

def test_xor_combination_diff_length():
    """Test XORing strings of different lengths. This should raise an error."""
    with pytest.raises(ValueError):
        xor_combination_hex("1c01", "686974207468652062756c6c277320657965")

def test_xor_combination_empty_strings():
    """Test XORing empty strings. Should return an empty string. This could also potentially be changed to raising an error."""
    assert xor_combination_hex("", "") == ""

def test_invalid_hex_string():
    """Test providing an invalid hex string."""
    with pytest.raises(ValueError):
        xor_combination_hex("1c01zg", "6869zy")

def test_xor_combination_single_byte():
    """Test XORing single byte hex strings."""
    assert xor_combination_hex("1c", "68") == "74"
