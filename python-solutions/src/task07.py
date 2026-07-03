## AES in ECB mode

from Crypto.Cipher import AES
from src.task04 import read_file_into_lines
import base64
import os

def decrypt_with_aes_ecb(file_name, key_string):
    """Takes a file_name and a key as a string as parameters and calls aes_ecb_decryption to perform AES decryption in ECB mode"""
    lines = read_file_into_lines(file_name)
    b64_file_data = ('').join(lines)
    bytes_file_data = base64.b64decode(b64_file_data) #Entire file is converted to bytes
    key_bytes = key_string.encode('utf-8')
    return aes_ecb_decryption(bytes_file_data, key_bytes)


def aes_ecb_decryption(bytes_file_data, key_bytes):
    """Uses the Crypto.Cipher library to perofrm decryption AES in ECB mode"""

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    plaintext = cipher.decrypt(bytes_file_data)
    return plaintext

if __name__ == '__main__':
    print(f"\nExecuting challenge 7 of cryptopals. Challenge involves AES in ECB mode\n")

    KEY = "YELLOW SUBMARINE"
    FILE_NAME = os.path.join(os.path.dirname(__file__), "task07.txt")
    result = decrypt_with_aes_ecb(FILE_NAME, KEY)

    print("Running the AES with ECB decryption...\n")

    print("Decrypted message: \n")
    print(result.decode("latin1"))