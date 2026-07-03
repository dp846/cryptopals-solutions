import pytest
from src.task03 import xor, score_text_naive, score_text_improved, decode_string

def test_xor():
    result = xor("1a", bytes([0x0f]))
    assert result == bytes([0x15])

def test_score_text_naive():
    score = score_text_naive(b"hello")
    expected_score = sum([1/1, 1/4, 1/1, 1/1, 1/1])  # Based on the scrabble values provided
    assert score == expected_score

def test_score_text_improved():
    score = score_text_improved(b"hello")
    # Compute expected score based on the frequency values provided
    expected_score = sum([10*0.06094, 10*0.12702, 10*0.04025, 10*0.04025, 10*0.07507])
    assert score == expected_score