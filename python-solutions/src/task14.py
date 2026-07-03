## Byte-at-a-time ECB decryption (Harder)

import random
from src.task10 import aes_ecb_decryption, aes_ecb_encryption
from src.task11 import generate_random_key
from src.task12 import byte_by_byte_ecb_decryption

def generate_random_prefix():
    """Generate a prefix for the orcale function - will have a random length and random contents"""
    return bytes([random.randint(0, 255) for _ in range(random.randint(1,24))])

def aes_ecb_oracle_random_prefix(controlled_bytes, key_bytes):
    """Takes in prefix bytes and will concatenate them to the unknown message bytes, performing AES encryption in ECB mode with the provided key. Returns the result"""
    
    UNKNOWN_BYTES = b"noone will ever be able to decrypt the contents of this message..."

    # Add the random prefix of bytes and the controlled bytes to the unknown bytes
    combined_plaintext_bytes = random_prefix + controlled_bytes + UNKNOWN_BYTES
    encrypted_bytes = aes_ecb_encryption(combined_plaintext_bytes, key_bytes)
    
    return encrypted_bytes

def print_in_blocks(ct_or_pt, BLOCK_SIZE=16):
    """Outputs plaintext or ciphertext in blocks, for visual debugging and clarity"""
    blocks = to_blocks(ct_or_pt)
    for b_number, b in enumerate(blocks, start=1):
        print(f"Block {b_number} -- {b.hex()}")
    print("\n")

def to_blocks(data, BLOCK_SIZE=16):
    """Given bytes data, will return a list of this data split into blocks of a given size (default 16)"""
    return [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

# ----------------------------- #

# X X X X X X X X -> CONSTANT
# X X 0 P L A I N -> asdfghjk
# T E X T 4 4 4 4 -> zxcvbnmn

# X X X X X X X X -> CONSTANT
# X X 0 0 P L A I -> lkjghfsd
# N T E X T 3 3 3 -> nmnbvcxz

# .
# .
# .

# X X X X X X X X -> CONSTANT
# X X 0 0 0 0 0 P -> lkjghfsd
# L A I N T E X T -> nmnbvcxz
# 8 8 8 8 8 8 8 8 -> oiuxzycv - full block of padding, now know    prefixlength + inputlength + plaintextlength = 3*blocksize

# .
# .
# .

# X X X X X X X X -> CONSTANT
# X X 0 0 0 0 0 0 -> qwertyui
# P L A I N T E X
# T 7 7 7 7 7 7 7

# X X X X X X X X -> CONSTANT
# X X 0 0 0 0 0 0 -> qwertyui - unchanged from last step, now know    prefixlength = 2 blocklengths - numofzerosfromprevstep
# 0 P L A I N T E -> alkjhgvi
# X T 6 6 6 6 6 6 -> iuwucvbk

# now I can set up the block structure:

# X X X X X X X X
# X X 0 0 0 0 0 0
# P L A I N T E X
# T 7 7 7 7 7 7 7


def find_same_block_count(RANDOM_KEY):
    """Finds out and returns the number of identical ct blocks from the orcale, helpful for determining the length of the prefix. """

    ciphertext1 = aes_ecb_oracle_random_prefix(b"", RANDOM_KEY)
    ciphertext2 = aes_ecb_oracle_random_prefix(b"B", RANDOM_KEY)

    # Check which blocks changed / stayed same
    ciphertext1_blocks = to_blocks(ciphertext1)
    ciphertext2_blocks = to_blocks(ciphertext2)

    same_block_count = 0
    for b1, b2 in zip(ciphertext1_blocks, ciphertext2_blocks):
        if b1 == b2:
            same_block_count += 1
        else:
            break
    return same_block_count


def decrypt_byte(prefix_length, decrypted_bytes, BLOCK_SIZE, RANDOM_KEY): ### CHECK OVER THIS
    """Decrypts and returns a single byte after perofrming a similar process byte by byte from task 12. """

    # Calculate the number of controlled bytes to add before the byte I want to decrypt
    controlled_length = (BLOCK_SIZE - (prefix_length + len(decrypted_bytes) % BLOCK_SIZE) - 1) % BLOCK_SIZE
    controlled_data = b"B" * controlled_length

    # Dictionary to map ciphertext blocks to their corresponding end positioned block byte values
    bytes_dict = {}
    
    for byte_value in range(256): # 0 to 255
        controlled_and_byte = controlled_data + decrypted_bytes + bytes([byte_value])
        ciphertext = aes_ecb_oracle_random_prefix(controlled_and_byte, RANDOM_KEY)
        block_index = (prefix_length + controlled_length + len(decrypted_bytes)) // BLOCK_SIZE
        bytes_dict[ciphertext[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]] = byte_value

    real_ciphertext = aes_ecb_oracle_random_prefix(controlled_data, RANDOM_KEY)

    block_index = (prefix_length + controlled_length + len(decrypted_bytes)) // BLOCK_SIZE
    real_block = real_ciphertext[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]

    return bytes([bytes_dict[real_block]]) # Returns the byte value from the matching generated plaintext

def byte_by_byte_ecb_decryption_harder(RANDOM_KEY, BLOCK_SIZE):

    ### Figure out the length of the unknown plaintext

    # First, figure out how many blocks the random prefix spans
    same_block_count = find_same_block_count(RANDOM_KEY)

    # Now loop through and find when the num of ct blocks increase - this means a full block of padding and we will know
    # prefixlength + inputlength + plaintextlength = (n-1) * blocksize

    prev_ciphertext = aes_ecb_oracle_random_prefix(b"", RANDOM_KEY)
    controlled_data = b""

    controlled_length_needed = 100000 # stores the controlled bytes length needed to have the plaintext message start on the next block

    for i in range(BLOCK_SIZE):
        controlled_data = b"A" * (i+1) #Add a byte
        ciphertext = aes_ecb_oracle_random_prefix(controlled_data, RANDOM_KEY)
            
        if len(ciphertext) != len(prev_ciphertext): # Must be a full block of padding just applied
            ct_length_no_padding = len(prev_ciphertext)
            length_for_ct_increase = len(controlled_data) - 1
            
            print(f"\nThe length of the prefix + controlled bytes + unknown bytes w/o padding block is {ct_length_no_padding} - this has been worked out")
            print(f"The length of the controlled bytes for a full block of padding to be applied is {length_for_ct_increase} - this value has been worked out")
            print(f"The length of the prefix is still unknown!")
            print(f"The length of the unknown bytes is still unknown!")

        ct_blocks = to_blocks(ciphertext)
        prev_ct_blocks = to_blocks(prev_ciphertext)

        if ct_blocks[same_block_count] == prev_ct_blocks[same_block_count]: # have now made the next ct block identical with enough controlled bytes
            controlled_length_needed = min((len(controlled_data) - 1), controlled_length_needed) # length needed was the length used for the prev ciphertext

        controlled_length = len(controlled_data) - 1 # To store the number of controlled bytes needed to fit into blocks EXACTLY (a block of padding)
        prev_ciphertext = ciphertext

    print(f"\nThe number of bytes needed for the plaintext to start in the next block is {controlled_length_needed}")

    prefix_length = (same_block_count+1) * BLOCK_SIZE - controlled_length_needed
    print(f"\nThe prefix length therefore must be {prefix_length}")

    unknown_length = ct_length_no_padding - length_for_ct_increase - prefix_length
    print(f"\nSo the unknown plaintext length must be {unknown_length}\n")

    ### Now I can actually do some decryption

    # The logic should be mostly the same as task12, main difference will be the prefix length
    # I should be able to reuse the code for task 12 provided I pad the controlled bytes to fill a block

    decrypted_message = b""
    for _ in range(unknown_length):
        decrypted_byte = decrypt_byte(prefix_length, decrypted_message, BLOCK_SIZE, RANDOM_KEY)
        decrypted_message += decrypted_byte

    return decrypted_message


# X X X X X X X X X X X X X X X X
# X X 0 0 0 0 0 0 0 0 0 0 0 0 0 0
# A A A A A A A A A A A A A A A H
# E L L O W O R L D I A M H E R E

# X X X X X X X X X X X X X X X X
# X X 0 0 0 0 0 0 0 0 0 0 0 0 0 0
# A A A A A A A A A A A A A A A Z
# H E L L O T H E R E . . .

    


# Values should not change for repeated oracle calls
random_prefix = generate_random_prefix()

if __name__ == '__main__':
    print(f"\nExecuting challenge 14 of cryptopals. Challenge involves a more difficult version of ECB decryption\n")

    BLOCK_SIZE = 16
    RANDOM_KEY = generate_random_key()

    print("For debugging:\n")
    print(f"The key is  {RANDOM_KEY.hex()}")
    print(f"The random prefix is  {random_prefix.hex()}")

    print("\nPerforming the decryption process...\n\n")
    result = byte_by_byte_ecb_decryption_harder(RANDOM_KEY, BLOCK_SIZE)
    print(f"Decrypted Message: {result}")