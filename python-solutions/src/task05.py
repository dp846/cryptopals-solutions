## Implement repeating-key XOR

def xor_on_bytes(bytes1, bytes2):
    """Performs XOR on two bytestreams and returns the resulting bytes in a bytearray."""
    
    if len(bytes1) != len(bytes2):
        raise ValueError("Both byte sequences must have the same length for XOR.")

    return bytearray([byte1 ^ byte2 for byte1, byte2 in zip(bytes1, bytes2)]) # Bitwise xor on each byte and combine them with zip


def extend_key_repeated(key, length):
    """Provided a key, extends it to a given length repeating it until it reaches a specified length."""
    
    repetitions = (length // len(key)) + 1
    return (key * repetitions)[:length]

def repeating_key_xor(text_bytes, key_bytes):
    """Encrypt some plaintext bytes with a given key using repeating key XOR"""

    if len(text_bytes) == 0:
        raise ValueError("No text provided")
    if len(key_bytes) == 0:
        raise ValueError("No key provided")
    
    repeating_key = extend_key_repeated(key_bytes, len(text_bytes))
    result_bytes = xor_on_bytes(text_bytes, repeating_key)

    return result_bytes

if __name__ == '__main__':
    print(f"\nExecuting challenge 5 of cryptopals. Challenge involves repeating key XOR\n")

    text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    text_bytes = text.encode()
    key_bytes = key.encode()

    print(f"Performing repeating key XOR with plaintext   {text_bytes}   and key   {key_bytes}")
    result_in_hex = repeating_key_xor(text_bytes, key_bytes).hex()

    print(f"Expected: {expected_result}")
    print(f"Result: {result_in_hex}")

