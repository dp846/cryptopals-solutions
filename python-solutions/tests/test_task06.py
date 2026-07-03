import pytest
from src.task06 import find_hamming_distance

def test_hamming_distance():
    test_str1 = "this is a test"
    test_str2 = "wokka wokka!!!"
    expected = 37
    assert find_hamming_distance(test_str1.encode(), test_str2.encode()) == expected

