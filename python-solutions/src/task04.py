## Detect single-character XOR

import os
from src.task03 import decode_string

def read_file_into_lines(file_name):
    """Reads the input text file given a filename, strips it of newline characters and then returns a list of all the lines"""

    with open(file_name, 'r') as read_file:
        lines = [line.strip() for line in read_file if line.strip() != '']
    return lines

def find_encrypted_line(file_name):
    """Loops through a file and does decode_string on each line, keeping track of the most likely line given the scoring defined in task3. Returns the top guess"""
    
    lines = read_file_into_lines(file_name)
    top_guess = (0, None)
    for line_num, line in enumerate(lines, start = 1):
        possible = decode_string(line)

        if top_guess[0] < possible[0]: # Update the message guess if its score is higher than the current top guess
            top_guess = possible
            
    return top_guess

if __name__ == '__main__' :
    print(f"\nExecuting challenge 4 of cryptopals. Challenge involves single character XOR within a file\n")

    FILE_NAME = os.path.join(os.path.dirname(__file__), 'task04.txt')
    _, top_possibility = find_encrypted_line(FILE_NAME)
    print(f'The most likely message is: {top_possibility}')