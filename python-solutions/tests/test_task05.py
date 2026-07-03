import pytest
from src.task05 import xor_on_bytes, extend_key_repeated, repeating_key_xor

def test_xor_on_bytes():
    bytes1 = bytearray([0x1c, 0x2f, 0x3a])
    bytes2 = bytearray([0x2f, 0x1c, 0x3a])
    result = xor_on_bytes(bytes1, bytes2)
    expected = bytearray([0x33, 0x33, 0x00])
    assert result == expected

def test_extend_key_repeated():
    key = bytearray(b'ICE')
    length = 10
    result = extend_key_repeated(key, length)
    expected = bytearray(b'ICEICEICEI')
    assert result == expected

def test_repeating_key_xor():
    text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    text_bytes = text.encode()
    key_bytes = key.encode()
    result_in_hex = repeating_key_xor(text_bytes, key_bytes).hex()
    assert result_in_hex == expected_hex

def test_repeating_key_xor_empty_text():
    with pytest.raises(ValueError, match="No text provided"):
        repeating_key_xor(bytearray(), bytearray(b'ICE'))

def test_repeating_key_xor_empty_key():
    with pytest.raises(ValueError, match="No key provided"):
        repeating_key_xor(bytearray(b'Text'), bytearray())