## Byte-at-a-time ECB decryption (Simple)

from src.task11 import generate_random_key
from base64 import b64decode
from src.task10 import aes_ecb_encryption
from src.task08 import find_duplicate_blocks

def aes_128_ecb_encryption_oracle(prefix_bytes, key_bytes):
    """Takes in prefix bytes and will concatenate them to the unknown message bytes, performing AES encryption in ECB mode with the provided key. Returns the result"""
    
    # Sets up the unknown message for the oracle to use
    UNKNOWN_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    UNKNOWN_BYTES = b64decode(UNKNOWN_B64)

    combined_plaintext_bytes = prefix_bytes + UNKNOWN_BYTES
    encrypted_bytes = aes_ecb_encryption(combined_plaintext_bytes, key_bytes)

    return encrypted_bytes

def find_block_size(RANDOM_KEY):
    """
    Will discover the block size used by the aes encryption function by observing when the ciphertext 
    increases in length and by how much when fed an increasing number of preceeding bytes.
    """

    initial_length = len(aes_128_ecb_encryption_oracle(b'', RANDOM_KEY))
    i = 1
    while True:
        data = b'A' * i
        new_length = len(aes_128_ecb_encryption_oracle(data, RANDOM_KEY))
        if new_length != initial_length:
            block_size = new_length - initial_length
            unknown_bytes_length = new_length - len(data) - block_size
            return block_size, unknown_bytes_length
        i += 1

        if i > 10000:
            raise Exception("Block size not found")


def byte_by_byte_ecb_decryption(oracle_function, RANDOM_KEY, block_size, unknown_bytes_length):
    """Performs byte by byte decryption by controlling the prefix of bytes given to the encryption oracle function."""

    decrypted_part = b"" # This will store the plaintext and build it up byte by byte

    for block_number in range(1, (unknown_bytes_length // block_size) + 2):
        for decrypting_byte_index in range(block_size):

            crafted_block = b"A" * (block_size - decrypting_byte_index - 1)
            
            # Take the block 'AAAAAAA' + 'XYZ...' where the X will then be a byte in the unknown bytes that we are decrypting
            # This makes it so AAAAAAAX makes up a block, then AAAAAAXY, then AAAAAXYZ ....
            encrypted_block_crafted = oracle_function(crafted_block, RANDOM_KEY)[:block_size*block_number]
            bytes_dictionary = {}

            for byte_value in range(256): # Try out each possible byte value exhaustively

                crafted_input = crafted_block + decrypted_part + bytes([byte_value])

                # Try out 'AAAAA....AA' + 'B' + 'unknown_bytes' - only the crafted input AAAAAAAB care about. All values for B are tried from 0, 1 ... to 255
                # Return a sliced section of the ciphertext so far based on the current block being decrypted.
                resulting_ciphertext = oracle_function(crafted_input, RANDOM_KEY)[:block_size*block_number] 
                bytes_dictionary[resulting_ciphertext] = byte_value 
            
            # Retrieve the byte value and add it to the ongoing decrypted message
            discovered_byte_value = bytes_dictionary[encrypted_block_crafted]
            decrypted_part += bytes([discovered_byte_value])
            
            # This is to prevent key errors, given that we know the length of the message we should get, we know when to stop
            if len(decrypted_part) == unknown_bytes_length:
                return decrypted_part
    
    return decrypted_part




if __name__ == '__main__':
    print(f"\nExecuting challenge 12 of cryptopals. Challenge involves byte-at-a-time ECB decryption\n")


    # Sets up the unknown message for the oracle to use
    UNKNOWN_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    UNKNOWN_BYTES = b64decode(UNKNOWN_B64)

    RANDOM_KEY = generate_random_key() # Generates a random key for the session (16 bytes)
    print(f"Generated random key (hex):  {RANDOM_KEY.hex()}\n")

    plaintext_bytes = b"ABC123"*1000
    encrypted_message = aes_128_ecb_encryption_oracle(plaintext_bytes, RANDOM_KEY)

    # Find the block size
    block_size, unknown_bytes_length = find_block_size(RANDOM_KEY)

    # Detect the use of ECB (from earlier task)
    if find_duplicate_blocks(encrypted_message, block_size):
        print("The use of ECB was detected: duplicate blocks found\n")
        print("Performing decryption...\n\n")

        result = byte_by_byte_ecb_decryption(aes_128_ecb_encryption_oracle, RANDOM_KEY, block_size, unknown_bytes_length) # Performs byte by byte decryption given ECB was used

        print(f"Expected: {UNKNOWN_BYTES.decode('latin1')}")
        print(f"Result: {result.decode('latin1')}")
    else:
        print("ECB was not detected - cannot perform decryption")



