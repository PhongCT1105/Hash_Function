# Hasing library for SHA-256
import hashlib

# Pack and Unpack library for binary data
import struct

# Multi-threading library for concurrent execution
from concurrent.futures import ThreadPoolExecutor

def sha256_pad(message: bytes) -> bytes:

    m_len = len(message) * 8
    
    # Step 1: Append a single '1' bit to the message
    message += b'\x80'
    
    # Step 2: Append '0' bits until the length is congruent to 448 modulo 512
    message += b'\x00' * ((56 - (len(message) % 64)) % 64)
    
    # Step 3: Append the length of the original message as a 64-bit big-endian integer
    message += struct.pack('>Q', m_len)
    return message

# Example usage
message = b"abc"
padded_message = sha256_pad(message)
print(padded_message.hex())
print(len(padded_message))
print(padded_message.decode('utf-8', errors='ignore'))
