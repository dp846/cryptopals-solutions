## CBC bitflipping attacks

from src.task10 import aes_cbc_encryption, aes_cbc_decryption
from src.task11 import generate_random_key
from src.task05 import xor_on_bytes

BLOCK_SIZE = 16
KEY = generate_random_key()
IV = generate_random_key()

def aes_cbc_prepend_and_encrypt(input):
    """Prepends and appends to an input stream of bytes, after parsing characters are removed"""

    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    input_validated = bytearray()

    for i, b in enumerate(input):
        if b == ord("=") or b == ord(";"):
            input_validated.append(ord("_"))
        else:
            input_validated.append(b)

    combined = prepend + input_validated + append
    print(f"Encrypting: {combined}")
    ciphertext = aes_cbc_encryption(combined, KEY, IV, BLOCK_SIZE)

    return ciphertext

def check_for_admin(ciphertext):
    """Decrypts a ciphertext and then checks whether it contains the admin flag substring within the plaintext."""

    plaintext = aes_cbc_decryption(ciphertext, KEY, IV, BLOCK_SIZE)

    print(f"Resuling plaintext: {plaintext}")

    admin_flag = b";admin=true;"

    if admin_flag in plaintext:
        print("PASS: ADMIN FOUND")
        return True
    else:
        print("FAIL: ADMIN NOT FOUND")
        return False

if __name__ == "__main__":
    print(f"\nExecuting challenge 16 of cryptopals. Challenge involves CBC bitflipping attacks\n")

    two_block_input = b"A" * 2 * BLOCK_SIZE
    nulling_mask = b"A" * BLOCK_SIZE
    admin_mask = b"XXXX;admin=true;"
    block_pos = 3 # We want to tamper with the 3rd block

    ct = aes_cbc_prepend_and_encrypt(two_block_input)
    third_ct_block = ct[(block_pos-1) * BLOCK_SIZE : block_pos * BLOCK_SIZE]

    print("XORing...")

    # XOR the null mask with admin flag block
    xor_result = xor_on_bytes(admin_mask, nulling_mask)

    # XOR that last xor result with the 3rd ct block
    admin_attack_block = xor_on_bytes(xor_result, third_ct_block)

    print("Combining the resul of the XOR operations back in with the original ciphertext...")

    # Insert it back into the 3rd block position of the ciphertext
    tampered_ct = ct[:(block_pos-1) * BLOCK_SIZE] + admin_attack_block + ct[block_pos * BLOCK_SIZE:]

    # Check for presence of the admin flag
    check_for_admin(tampered_ct)
