## ECB cut-and-paste

from src.task09 import apply_pkcs7_padding, strip_pkcs7_padding
from src.task10 import aes_ecb_encryption, aes_ecb_decryption
from src.task11 import generate_random_key

def cookie_parsing(string):
    """
    Should parse a string in the format a=b&c=d as
    {
        a: 'b',
        c: 'd'
    }
    """
    cookie_dict = {}
    separated_strings = string.split("&")

    for kv_str in separated_strings:
        if kv_str.count("=") != 1:
            raise ValueError("The string given is not in the correct format")

        kv_str = kv_str.split("=")
        k = kv_str[0]
        v = kv_str[1]
        cookie_dict[k] = v

    return cookie_dict

def profile_for(email):
    """Takes in an email address as bytes and prodcues a dictionary object"""

    if b"=" in email or b"&" in email:
        raise ValueError("Email should not include these characters")
    
    profile_dict = {
        b'email': email,
        b'uid': b'10',
        b'role': b'user'
    }

    return profile_dict


def dict_encoder(dict_obj):
    """Encodes a dictionary of a profile into the format specified, using = and &"""
    encoded_strings = []
    for key, value in dict_obj.items():
        kv_entry = key + b"=" + value
        encoded_strings.append(kv_entry)
    
    final_encoded_str = (b"&").join(encoded_strings)
    return final_encoded_str

def print_in_blocks(data, block_size=16):
    """Prints a byte string in block-size increments."""
    for i in range(0, len(data), block_size):
        print(data[i:i+block_size])


if __name__ == '__main__':
    print(f"\nExecuting challenge 13 of cryptopals. Challenge involves ECB encrypted profile tokens\n")

    # Check the string parses correctly into a dictionary
    cookie_string = "foo=bar&baz=qux&zap=zazzle"
    print(f"Running the cookie parser for  {cookie_string}")
    cookie_obj = cookie_parsing(cookie_string)
    print(f"Result: {cookie_obj}\n")

    # Check the profile is created and then encoded correctly as bytes
    print("\nRunning the profile creator... ")
    profile_dict = profile_for(b"foo@bar.com")
    profile_bytes = dict_encoder(profile_dict)
    print(profile_bytes)

    # Generate random AES key
    RANDOM_KEY = generate_random_key()

    # Goal is to give ourselves a role=admin token. This can be done by:
    # - having an email long enough to fit the block size such that-
    # - we can add a block containing b'admin' + padding within the email (the profile_for is the orcale)
    # - then rearrange the blocks at the end combining two prfiles
    
    # No admin structure:
    # e m a i l = f o o @ b a r r r .   BLOCK 1 - NA
    # c o m & u i d = 1 0 & r o l e =   BLOCK 2 - NA
    # u s e r 0 0 0 0 0 0 0 0 0 0 0 0   BLOCK 3 - NA

    # With admin padding block structure: 
    # e m a i l = f o o @ b a r r r .   BLOCK 1 - A
    # a d m i n 0 0 0 0 0 0 0 0 0 0 0   BLOCK 2 - A
    # c o m & u i d = 1 0 & r o l e =   BLOCK 3 - A
    # u s e r 0 0 0 0 0 0 0 0 0 0 0 0   BLOCK 4 - A

    # Final structure - take blocks 1 and 2 from the no admin structure and then insert block 2 of the admin structure on the end

    # e m a i l = f o o @ b a r r r .   BLOCK 1 - NA
    # c o m & u i d = 1 0 & r o l e =   BLOCK 2 - NA
    # a d m i n 0 0 0 0 0 0 0 0 0 0 0   BLOCK 2 - A

    print("\nGetting admin token ...")

    email1 = b"foo@barrr.com"
    profile_dict1 = profile_for(email1)
    profile_bytes_no_admin = dict_encoder(profile_dict1)

    print("\nProfile blocks without admin: ")
    print_in_blocks(profile_bytes_no_admin) # Prints 16 byte blocks

    admin_padded_block = apply_pkcs7_padding(b"admin") 
    email_with_admin = b"foo@barrr." + admin_padded_block + b"com"
    profile_dict = profile_for(email_with_admin)
    profile_bytes_with_admin = dict_encoder(profile_dict)

    print("\nProfile blocks with admin: ")
    print_in_blocks(profile_bytes_with_admin) # Prints 16 byte blocks

    encrypted_user_profile = aes_ecb_encryption(profile_bytes_no_admin, RANDOM_KEY)
    encrypted_admin_profile = aes_ecb_encryption(profile_bytes_with_admin, RANDOM_KEY)

    # I take the first two blocks of the no admin profile (ending with b"...role="") and add on block 2 
    # of the admin profile (the ciphertext block corresponding to b"admin\x0b\x0b.....")
    encrypted_crafted_profile = encrypted_user_profile[:32] + encrypted_admin_profile[16:32]

    decrypted_crafted_profile = aes_ecb_decryption(encrypted_crafted_profile, RANDOM_KEY)
    print(f"\nThe resulting encrypted admin profile token is:  {encrypted_crafted_profile}")
    print(f"\nThe resulting decrypted admin profile token is:  {strip_pkcs7_padding(decrypted_crafted_profile)}")


    
