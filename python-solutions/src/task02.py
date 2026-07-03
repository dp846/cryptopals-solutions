## Fixed XOR

def xor_combination_hex(buffer1, buffer2):
    """Applies XOR to two buffers of hex provided they are the same length and returns the result"""
    if len(buffer1) != len(buffer2):
        raise ValueError ("Buffers are not equal in length")
    
    if not buffer1 and not buffer2:
        return "" # If both buffers are empty then an empty hex string should be returned (could be changed to an error really depending on desired behaviour)
    
    # Hex conversions
    num1 = int(buffer1, 16)
    num2 = int(buffer2, 16)

    result = num1 ^ num2 # Bitwise XOR
    hex_result = hex(result)[2:] # Convert to hex and remove '0x' prefix

    return hex_result

if __name__ == '__main__' :
    print(f"\nExecuting challenge 2 of cryptopals. Challenge involves using fixed XOR\n")

    hex_str = "1c0111001f010100061a024b53535009181c"
    xor_str = "686974207468652062756c6c277320657965"
    expected_result = "746865206b696420646f6e277420706c6179"

    print(f"XORing   {hex_str}   with   {xor_str} ...")
    print(f"\nResult: {xor_combination_hex(hex_str, xor_str)}")
    print(f"Expected: {expected_result}")