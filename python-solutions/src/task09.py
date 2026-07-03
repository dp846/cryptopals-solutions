## Implement PKCS#7 padding

def apply_pkcs7_padding(plaintext_bytes, block_size=16):
    """Applies padding to input plaintext to evenly fit a given block size."""

    padding_count = block_size - (len(plaintext_bytes) % block_size)
    padding_bytes = bytes([padding_count]) * padding_count

    return plaintext_bytes + padding_bytes

def strip_pkcs7_padding(plaintext_bytes):
    """Checks for the use of pkcs7 padding on some bytes, and strips it off if found"""
    final_byte = plaintext_bytes[-1]

    # Check if the final byte is an invalid padding byte or not, returning the plaintext bytes stripped or unstripped accordingly.
    if final_byte == 0 or final_byte > len(plaintext_bytes) or not (plaintext_bytes.endswith(bytes([final_byte]*final_byte))):
        return plaintext_bytes
    else:
        return plaintext_bytes[:-int(final_byte)]
    


if __name__ == '__main__':
    print(f"\nExecuting challenge 9 of cryptopals. Challenge involves implementing PKCS#7 padding\n")

    PLAINTEXT = b"YELLOW SUBMARINE"
    BLOCK_SIZE = 20
    
    print(f"Plaintext bytes:  {PLAINTEXT}")

    padded_bytes = apply_pkcs7_padding(PLAINTEXT, BLOCK_SIZE)
    print(f"Padded plaintext bytes:  {padded_bytes}")

    stripped_bytes = strip_pkcs7_padding(padded_bytes)
    print(f"Stripped plaintext bytes: {stripped_bytes}")