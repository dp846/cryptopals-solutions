## Implement CBC mode

import os
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from src.task05 import xor_on_bytes
from src.task09 import apply_pkcs7_padding, strip_pkcs7_padding
from src.task07 import aes_ecb_decryption

def aes_key_validation(key):
    """Validate the key length for AES encryption."""
    key_length = len(key) * 8  # Convert byte length to bit length
    if key_length not in [128, 192, 256]:
        raise ValueError(f"Invalid key length for AES: {key_length} bits. Supported sizes are 128, 192, or 256 bits")

def aes_ecb_encryption(plaintext_bytes, key_bytes):
    """Takes in plaintext bytes and a key as bytes, and performs AES encryption in ECB mode using the Crypto.Cipher library"""

    if (len(plaintext_bytes) % 16):
        plaintext_bytes = apply_pkcs7_padding(plaintext_bytes)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext_bytes)
    return encrypted

def read_file_into_lines(file_name):
    """Reads the input text file, strips it of newline characters and then returns a list of all the lines"""
    with open(file_name, 'r') as read_file:
        lines = [line.strip() for line in read_file]
    return lines

def file_decryption_aes_cbc(file_name, key_string, init_vec):
    """Calls AES decryption in CBC mode after bytes conversion.
    Given a filename of a file containing b64 ciphertext, a key, and an initialisation vector, 
    will return the decrypted contents of the file using AES CBC decryption.
    """
    aes_key_validation(key_string)
    ciphertext = ''.join(read_file_into_lines(file_name))
    ciphertext_bytes = b64decode(ciphertext)

    key_bytes = key_string.encode('utf-8')

    return aes_cbc_decryption(ciphertext_bytes, key_bytes, init_vec)

def aes_cbc_decryption(ciphertext_bytes, key_bytes, init_vec, BLOCK_SIZE=16):
    """Performs AES decryption in CBC mode."""

    decrypted = b''
    ciphertext_blocks = [ciphertext_bytes[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext_bytes), BLOCK_SIZE)]

    prev_ciphertext = init_vec

    for current_ciphertext in ciphertext_blocks:
        decrypted_block = aes_ecb_decryption(current_ciphertext, key_bytes)
        plaintext_block = xor_on_bytes(prev_ciphertext, decrypted_block)

        decrypted += plaintext_block
        prev_ciphertext = current_ciphertext

    return strip_pkcs7_padding(decrypted) #Strip the padding bytes before returning

def aes_cbc_encryption(plaintext_bytes, key_bytes, init_vec, BLOCK_SIZE=16):
    """Performs AES encryption in CBC mode."""
        
    padded_plaintext = apply_pkcs7_padding(plaintext_bytes) #Will apply padding even if it is a multiple of block size
    plaintext_blocks = [padded_plaintext[i:i+BLOCK_SIZE] for i in range(0, len(padded_plaintext), BLOCK_SIZE)]
    encrypted = b''

    prev_ciphertext = init_vec

    for plaintext_block in plaintext_blocks:
        xor_result = xor_on_bytes(prev_ciphertext, plaintext_block)
        encrypted_block = aes_ecb_encryption(xor_result, key_bytes)

        encrypted += encrypted_block
        prev_ciphertext = encrypted_block  

    return encrypted

if __name__ == '__main__':
    print(f"\nExecuting challenge 10 of cryptopals. Challenge involves implementing CBC mode\n")

    # Testing AES encryption with ECB
    KEY = b"YELLOW SUBMARINE"
    plaintext = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
    encrypted = aes_ecb_encryption(plaintext, KEY)

    print(f"The ciphertext using AES ECB encryption: \n\n{b64encode(encrypted)}\n\nThe above base64 should match task07.txt")
    
    # Running the CBC decryption
    FILE_NAME = os.path.join(os.path.dirname(__file__), 'task10.txt')
    KEY_STRING = 'YELLOW SUBMARINE'
    IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    result = file_decryption_aes_cbc(FILE_NAME, KEY_STRING, IV)
    print(f"\nThe plaintext result after decryption is: \n\n{result.decode('latin-1')}")

