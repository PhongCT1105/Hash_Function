import struct
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

###############################
# Step 1: Padding and Splitting
###############################

def sha256_pad(message: bytes) -> bytes:
    """
    Pad the message according to the SHA-256 specification.
    """
    m_len = len(message) * 8  # message length in bits
    message += b'\x80'  # Append the 1 bit (as 0x80)
    # Append 0 bytes until length is 448 mod 512 bits 
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
    W = list(struct.unpack('>16L', block))
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

    # Return new state: add the compressed chunk to the IV.
    return [(iv[i] + val) & 0xFFFFFFFF for i, val in enumerate([a, b, c, d, e, f, g, h])]

#####################################################
# Step 3: Reduction Functions for Parallel Hashing
#####################################################

def reduce_iv(iv: list[int], block1: list[int], block2: list[int]) -> list[int]:
    """
    Update IV using: new_IV = IV + (block1 XOR block2)
    (Applied component-wise modulo 2^32.)
    """
    return [(iv[i] + (block1[i] ^ block2[i])) & 0xFFFFFFFF for i in range(8)]

def combine_hash_blocks(hash_blocks: list[list[int]], iv: list[int]) -> (list[bytes], list[int]):
    new_blocks = []
    new_iv = iv  # Option: you might decide to update the IV for each pair separately and combine them.
    # Instead of shifting, iterate over pairs.
    i = 0
    pair_ivs = []
    while i < len(hash_blocks):
        if i + 1 < len(hash_blocks):
            block1 = hash_blocks[i]
            block2 = hash_blocks[i + 1]
            # Compute new IV for this pair.
            pair_iv = reduce_iv(iv, block1, block2)
            pair_ivs.append(pair_iv)
            # Concatenate block1 and block2 into a 512-bit block.
            new_block = struct.pack(">8I", *block1) + struct.pack(">8I", *block2)
            new_blocks.append(new_block)
            i += 2
        else:
            # If there's an odd block, pass it along.
            new_blocks.append(struct.pack(">8I", *hash_blocks[i]))
            i += 1

    # For simplicity, choose the first pair's IV as the new IV (or combine all pair IVs as desired)
    if pair_ivs:
        new_iv = pair_ivs[0]
    return new_blocks, new_iv




#####################################################
# Step 4: Overall Parallel Reduction Process (with Trace)
#####################################################

def tree_reduce_parallel_trace(message: bytes, iv: list[int]) -> dict:
    trace = {}
    trace["originalMessage"] = message.decode("utf-8", errors="replace")
    padded = sha256_pad(message)
    trace["padded"] = padded.hex()
    blocks = split_blocks(padded)
    trace["blocks"] = [blk.hex() for blk in blocks]

    # Stage 1: Process each block with the given IV in parallel.
    with ThreadPoolExecutor() as executor:
        # To preserve order, simply use a list comprehension:
        futures = [executor.submit(sha256_compress_block, block, iv) for block in blocks]
        initialHashOutputs = [future.result() for future in futures]
    trace["initialHashOutputs"] = [struct.pack(">8I", *h).hex() for h in initialHashOutputs]

    hash_outputs = initialHashOutputs
    rounds = []
    round_number = 0
    # For very short messages that produce only one block, no rounds occur.
    while len(hash_outputs) > 1:
        round_info = {}
        round_info["round"] = round_number
        round_info["inputHashOutputs"] = [struct.pack(">8I", *h).hex() for h in hash_outputs]
        new_blocks, new_iv = combine_hash_blocks(hash_outputs, iv)
        round_info["computedNewIV"] = struct.pack(">8I", *new_iv).hex()
        round_info["newBlocks"] = [blk.hex() for blk in new_blocks]
        
        new_hash_outputs = []
        with ThreadPoolExecutor() as executor:
            futures = []
            for blk in new_blocks:
                if len(blk) == 64:
                    futures.append(executor.submit(sha256_compress_block, blk, new_iv))
                elif len(blk) == 32:
                    # Simply unpack the 256-bit block.
                    futures.append(executor.submit(lambda b: list(struct.unpack(">8I", b)), blk))
                else:
                    raise ValueError("Unexpected block length.")
            new_hash_outputs = [future.result() for future in futures]
        round_info["outputHashOutputs"] = [struct.pack(">8I", *h).hex() for h in new_hash_outputs]
        rounds.append(round_info)
        iv = new_iv
        hash_outputs = new_hash_outputs
        round_number += 1

    final_digest = struct.pack(">8I", *hash_outputs[0]).hex()
    trace["finalDigest"] = final_digest
    trace["rounds"] = rounds

    # Debug prints (temporarily)
    print("DEBUG: Final digest =", final_digest)
    print("DEBUG: Trace =", trace)
    
    return {"finalDigest": final_digest, "trace": trace}

# Example usage for local testing.
if __name__ == "__main__":
    default_iv = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    # Example message: 56 bytes "a" + 1 byte "b" (total 57 bytes).
    message = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
    result = tree_reduce_parallel_trace(message, default_iv)
    print("Final parallel SHA-256 digest:", result["finalDigest"])
    print("Trace:", result["trace"])
