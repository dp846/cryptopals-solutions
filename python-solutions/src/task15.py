## PKCS#7 padding validation

def check_and_strip_padding(buffer, BLOCK_SIZE=16):
    """Validates a buffer to ensure it has the correct padding, and if so returns the data with stripped padding. Otherwise will raises an exception."""
    buffer_length = len(buffer)

    if buffer_length == 0:
        raise ValueError ("Buffer empty")
    
    final_byte = buffer[-1]
    
    if final_byte == 0 or final_byte > BLOCK_SIZE:
        raise ValueError ("Invalid padding")

    if (buffer[-final_byte:] != bytes([final_byte]*final_byte)):
        raise ValueError ("Invalid padding")
        
    return buffer[:-final_byte]



if __name__ == '__main__':
    
    data = b"ICE ICE BABY\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
    stripped_data = check_and_strip_padding(data)

    print(stripped_data)
