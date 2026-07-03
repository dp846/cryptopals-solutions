## Single-byte XOR cipher

def xor(hex_str, key):
    """Will return the result of performing the XOR operation on the hex string and the key (bytes) after first converting the hex string to bytes"""

    hex_bytes = bytes.fromhex(hex_str)
    return bytes(byte1 ^ byte2 for byte1, byte2 in zip (hex_bytes, key))

def score_text_naive(string):
    """Scores a given string based on the reciprocal of scores of Scrabble letters (first thing that came to mind but it also works in this task)"""
    score = 0
    scrabble_values = {
        'a': 1 , 'b': 3 , 'c': 3, 'd': 2, 'e': 1, 'f': 4, 'g': 2, 
        'h': 4, 'i': 1, 'j': 8, 'k': 5, 'l': 1, 'm': 3, 'n': 1, 
        'o': 1, 'p': 3, 'q': 10, 'r': 1, 's': 1 , 't': 1, 'u': 1, 
        'v': 8, 'w': 4, 'x': 8, 'y': 4, 'z': 10, ' ': 1
        }

    # Default value of 20 used (could really be anything roughly 10 or more) - prevents uncommon characters having high weightings
    # WARNING: should not be set to 0 - this will result in DivideByZero errors
    UNFOUND_CHAR_VALUE = 20

    # Score the bytes given their scrabble scores - if a value is not found in the dictionary, the reciprocal of value of UNFOUND_CHAR_VALUE is used
    # to minimise the score for unlikely characters
    score = sum(1 / (scrabble_values.get(chr(char).lower(), UNFOUND_CHAR_VALUE)) for char in string)
    return score

def score_text_improved(string):
    """Scores a given string based on more accurate frequency analysis values from online sources (https://mathcenter.oxford.emory.edu/site/math125/englishLetterFreqs/)"""
    
    english_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
        'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
        'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
        'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
        'z': 0.00074, ' ': 0.13000
    }

    ALPHABETICAL_MULTIPLIER = 10 # Size of this needs to be sufficient enough really, such that the weighting of alphabetical characters is high enough

    # Score the bytes given their frequency scores - if a value is not found in the dictionary, default value of 0 is used
    # to minimise the score for unlikely characters
    score = sum(ALPHABETICAL_MULTIPLIER * (english_freq.get(chr(char).lower(), 0)) for char in string)
    return score

def decode_string(encoded):
    """
    Given an encoded hex string finds the most likely plaintext messages using the scoring function.
    Loops through and tries each key out for a single byte xor cipher, keeping track of the the scores for each possible message.
    Returns a (score, message) tuple of the highest score and its message.
    """
    
    message_score_pairs = []

    for key in range(256):
        key_extended = len(encoded) * bytes([key])
        possible_message = xor(encoded, key_extended)

        score = score_text_improved(possible_message) # This could be changed to instead use the score_text_naive function instead
        message_score_pairs.append((score, possible_message.decode('latin-1'))) # Here the score is the first element of the pair so when sort is called, it sorts by scores

    message_score_pairs.sort()
    return message_score_pairs[-1] # This could be changed instead to return the top n most likely messages if needed

if __name__ == '__main__' :
    print(f"\nExecuting challenge 3 of cryptopals. Challenge involves a single byte XOR cipher\n")

    hex_encoded_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    _, top_possibility = decode_string(hex_encoded_string) # Unpack tuple and discard score

    print(f'The hex encoded string is:  {hex_encoded_string}')
    print(f'The most likely message is: {top_possibility}')
