import struct
import hashlib
from concurrent.futures import ThreadPoolExecutor

###############################
# Step 1: Padding and Splitting
###############################

def sha256_pad(message: bytes) -> bytes:
    """
    Pad the message according to the SHA-256 specification.
    """
    m_len = len(message) * 8  # message length in bits
    message += b'\x80'  # Append the 1 bit (as 0x80)
    # Append 0 bytes until length is 448 mod 512 bits (i.e. 56 mod 64 bytes)
    message += b'\x00' * ((56 - (len(message) % 64)) % 64)
    # Append original length as a 64-bit big-endian integer
    message += struct.pack('>Q', m_len)
    return message

def split_blocks(padded_message: bytes, block_size: int = 64) -> list[bytes]:
    """
    Split the padded message into 512-bit (64-byte) blocks.
    """
    return [padded_message[i:i+block_size] for i in range(0, len(padded_message), block_size)]

#####################################
# Step 2: Custom SHA-256 Compression
#####################################

def right_rotate(value: int, bits: int) -> int:
    """
    Right rotate a 32-bit integer.
    """
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

# SHA-256 round constants (first 32-bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def sha256_compress_block(block: bytes, iv: list[int]) -> list[int]:
    """
    Custom SHA-256 compression function that compresses a single 512-bit block using the provided IV.
    Returns a 256-bit output as a list of 8 32-bit integers.
    """
    assert len(block) == 64
    assert len(iv) == 8

    # Prepare the message schedule array W[0..63]
    W = list(struct.unpack('>16L', block))  # 16 words from the block
    for i in range(16, 64):
        s0 = right_rotate(W[i-15], 7) ^ right_rotate(W[i-15], 18) ^ (W[i-15] >> 3)
        s1 = right_rotate(W[i-2], 17) ^ right_rotate(W[i-2], 19) ^ (W[i-2] >> 10)
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)

    # Initialize working variables with the IV
    a, b, c, d, e, f, g, h = iv

    # Compression loop (64 rounds)
    for i in range(64):
        S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # Compute the new state: add the compressed chunk to the current hash value
    return [(iv[i] + val) & 0xFFFFFFFF for i, val in enumerate([a, b, c, d, e, f, g, h])]

#####################################################
# Step 3: Reduction functions for Parallel Hashing
#####################################################

def reduce_iv(iv: list[int], block1: list[int], block2: list[int]) -> list[int]:
    """
    Update IV using the formula: new_IV = IV + (block1 XOR block2) 
    (performed component-wise modulo 2^32).
    """
    return [(iv[i] + (block1[i] ^ block2[i])) & 0xFFFFFFFF for i in range(8)]

def combine_hash_blocks(hash_blocks: list[list[int]], iv: list[int]) -> (list[bytes], list[int]):
    """
    Given an array of 256-bit hash outputs (each a list of 8 ints) and an IV,
    do the following reduction step:
      1. Compute a new IV using the first two blocks.
      2. Shift the hash_blocks array to the right by one (i.e. drop the first element).
      3. Pair adjacent blocks from the shifted array by concatenating their bytes into a 512-bit block.
         If there is an odd block remaining, pass it along directly.
    Returns the new block array (list of bytes) and the updated IV.
    """
    # Compute new IV if at least two blocks exist:
    if len(hash_blocks) >= 2:
        new_iv = reduce_iv(iv, hash_blocks[0], hash_blocks[1])
    else:
        new_iv = iv

    # Shift the hash block array to the right by one:
    shifted = hash_blocks[1:]

    new_blocks = []
    i = 0
    while i < len(shifted):
        if i + 1 < len(shifted):
            # Concatenate two adjacent 256-bit blocks into one 512-bit block
            b1 = struct.pack(">8I", *shifted[i])
            b2 = struct.pack(">8I", *shifted[i+1])
            new_blocks.append(b1 + b2)
            i += 2
        else:
            # If odd, pass the remaining 256-bit block (32 bytes) as is.
            new_blocks.append(struct.pack(">8I", *shifted[i]))
            i += 1
    return new_blocks, new_iv

#####################################################
# Step 4: The Overall Parallel Reduction Process
#####################################################

def tree_reduce_parallel(message: bytes, iv: list[int]) -> bytes:
    """
    Build the parallel hash as follows:
     1. Pad and split the message.
     2. For each 512-bit block, compute a 256-bit hash using sha256_compress_block and the given IV.
     3. Then perform reduction rounds:
          a. Compute updated IV using the first two hash outputs.
          b. Shift the hash outputs one to the right.
          c. Pair adjacent 256-bit outputs (concatenating them into 512-bit blocks).
          d. Process each new block with sha256_compress_block using the updated IV.
          e. In case of an odd block, pass it directly (without hashing).
     4. Repeat until only one 256-bit hash remains.
    Return that final hash digest as bytes.
    """
    # Pad and split the message
    padded = sha256_pad(message)
    blocks = split_blocks(padded)  # list of 512-bit (64-byte) blocks

    # Stage 1: Process each block independently using the initial IV.
    hash_outputs = [sha256_compress_block(block, iv) for block in blocks]

    # Reduction rounds until only one hash output remains.
    while len(hash_outputs) > 1:
        # Compute new IV and new block list from the hash_outputs.
        new_blocks, new_iv = combine_hash_blocks(hash_outputs, iv)
        new_hash_outputs = []
        # Process each new block
        for blk in new_blocks:
            # Our compression function requires 64 bytes; if the block is 64 bytes,
            # we hash it; if it is only 32 bytes (odd leftover), we simply unpack it.
            if len(blk) == 64:
                new_hash_outputs.append(sha256_compress_block(blk, new_iv))
            elif len(blk) == 32:
                new_hash_outputs.append(list(struct.unpack(">8I", blk)))
            else:
                raise ValueError("Unexpected block length in reduction.")
        # Update IV and hash_outputs for next round.
        iv = new_iv
        hash_outputs = new_hash_outputs

    # Final output: convert the 256-bit hash (list of 8 ints) to bytes.
    final_hash = struct.pack(">8I", *hash_outputs[0])
    return final_hash

###############################
# Example Usage
###############################

# Define a default initial IV (can be customized)
default_iv = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

if __name__ == "__main__":
    # Example message
    message = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

    final_digest = tree_reduce_parallel(message, default_iv)
    print("Final parallel SHA-256 digest:", final_digest.hex())
