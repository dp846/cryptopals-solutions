## Break repeating-key XOR

import base64
import os
from src.task05 import xor_on_bytes, repeating_key_xor
from src.task04 import read_file_into_lines
from src.task03 import score_text_improved


def possible_key_lengths(bytes_file_data):
    """Find the most likely key sizes, and return a list of them."""

    min_key_size = 2
    max_key_size = 41

    distances_and_keys = []

    for KEYSIZE in range(min_key_size, max_key_size): #To find the key sizes with the lowest normalised hamming distances between blocks
        chunks = [bytes_file_data[i:i+KEYSIZE] for i in range(0, len(bytes_file_data), KEYSIZE)][:4]

        total_distance = 0

        for i in range(len(chunks) - 1):
            total_distance += find_hamming_distance(chunks[i], chunks[i + 1])

        normalized_distance = total_distance / (KEYSIZE) # Calculate the normalized Hamming distance
        distances_and_keys.append((normalized_distance, KEYSIZE))

    distances_and_keys.sort()

    NUM_OF_KEYSIZES = 4 #Number of different key sizes to try out
    top_n_keys = [key_size for distance, key_size in distances_and_keys[:NUM_OF_KEYSIZES]]

    return top_n_keys


def find_hamming_distance(bytes1, bytes2):
    """Finds the hammign distance between two bytes objects of the same length by doing XOR to find the number of differing bits"""
    xor_result = xor_on_bytes(bytes1, bytes2)
    binary_str = ""
    for byte in xor_result:
        binary_str += format(byte, '08b')
    
    bit_count = binary_str.count('1')
    return bit_count

def break_repeating_key_xor(file_name):
    """
    Given a file name, will open the file and break the encryption if a repeating key was used. 
    Returns the highest scoring message from all the most likely key sizes.
    """
    lines = read_file_into_lines(file_name)
    b64_file_data = ('').join(lines)
    bytes_file_data = base64.b64decode(b64_file_data) #Entire file is converted to bytes

    likely_key_sizes = possible_key_lengths(bytes_file_data) #Gives list of most likely key sizes, 2,3, 29 and 5
    scores_of_messages = [] #Will store a list of tuples for each message and its scores using frequency analysis used in earlier task.
    
    for KEY_SIZE in likely_key_sizes:
        data_in_blocks = [bytes_file_data[i:i+KEY_SIZE] for i in range(0, len(bytes_file_data), KEY_SIZE)]

        # Remove the last block if it has fewer elements than the other blocks, could also have padded with 0s
        if len(data_in_blocks[-1]) < KEY_SIZE:
            data_in_blocks.pop()

        #Transposing 
        transposed_data = [bytearray() for _ in range(KEY_SIZE)]
        for block in data_in_blocks:
            for index, byte in enumerate(block):
                transposed_data[index].append(byte)

        #Perform single byte xor on each new block of bytes - this returns the key that was used and appends it to a list
        best_keys = []
        for byte_block in transposed_data:
            _, most_likely_key = crack_single_byte_xor(byte_block)
            best_keys.append(most_likely_key)

        # Convert the key to bytes and then perform XOR on the entire file contents with the discovered key pieces
        key_bytes = bytes(best_keys)
        result = repeating_key_xor(bytes_file_data, key_bytes)

        scores_of_messages.append((score_text_improved(result), result.decode('latin1')))
    
    scores_of_messages.sort()
    _, highest_scoring_message = scores_of_messages[-1]

    return highest_scoring_message

def crack_single_byte_xor(encrypted):
    """Given encrypted bytes finds the most likely plaintext messages using the scoring functions, given the key is all one char and XOR was used"""
    highest_score_message = (0, True)
    best_key_guess = 0

    for key in range(256):
        key_extended = len(encrypted) * bytes([key])

        possible_message = xor_on_bytes(encrypted, key_extended)
        score = score_text_improved(possible_message)
        current_score_message =  (score, possible_message)

        if highest_score_message < current_score_message:
            score = score_text_improved(possible_message)
            highest_score_message = current_score_message
            best_key_guess = key

    return current_score_message, best_key_guess
    

if __name__ == '__main__':
    print(f"\nExecuting challenge 6 of cryptopals. Challenge involves breaking repeating key XOR\n")

    print("Testing the hamming distance...\n\n")

    test_str1 = "this is a test"
    test_str2 = "wokka wokka!!!"
    expected_result = 37
    distance_result = find_hamming_distance(test_str1.encode(), test_str2.encode())


    print(f"The hamming distance of  '{test_str1}'  and  '{test_str2}'  is  {distance_result}\n")
    print(f"Expected: {expected_result}")
    print(f"Result: {distance_result}\n")

    FILE_NAME = os.path.join(os.path.dirname(__file__), 'task06.txt')
    decrypted_message = break_repeating_key_xor(FILE_NAME)

    print("Running the single byte XOR cracker...\n\n")

    print("The most likely decrypted message was: \n\n")
    print(decrypted_message)

