## Convert hex to base 64

from base64 import b64encode, b64decode

def hex_to_b64(hex_str):
    """Converts hex to base 64 and returns the result"""
    return b64encode(bytes.fromhex(hex_str)).decode()

def b64_to_hex(b64_str):
    """Converts base 64 to hex and returns the result as a string of hex"""
    return b64decode(b64_str.encode('utf-8')).hex()

if __name__ == '__main__' :
    print(f"\nExecuting challenge 1 of cryptopals. Challenge involves converting hex to base 64")

    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    print(f"\nHex to base 64 result: {hex_to_b64(hex_str)}")
    print(f"Expected result: {b64_str}")

    print(f"\nBase 64 to hex result: {b64_to_hex(b64_str)}")
    print(f"Expected result was {hex_str}")
