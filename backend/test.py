import random
import string
import matplotlib.pyplot as plt
from sha256 import tree_reduce_parallel_trace

default_iv = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def random_string():
    length = random.randint(120, 1300) 
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def run_all_tests(num_samples=1000, num_buckets=64):
    hashes = set()
    collisions = 0
    buckets = [0] * num_buckets
    avalanche_diffs = []

    for _ in range(num_samples):
        s = random_string()
        digest = tree_reduce_parallel_trace(s.encode(), default_iv)["finalDigest"]

        # Collision
        if digest in hashes:
            collisions += 1
        else:
            hashes.add(digest)

        # Uniformity
        hash_int = int(digest, 16)
        buckets[hash_int % num_buckets] += 1

        # Avalanche
        modified = list(s)
        modified[0] = chr((ord(modified[0]) + 1) % 128)
        mod_str = ''.join(modified)
        mod_digest = tree_reduce_parallel_trace(mod_str.encode(), default_iv)["finalDigest"]

        base_bits = bin(int(digest, 16))[2:].zfill(256)
        mod_bits = bin(int(mod_digest, 16))[2:].zfill(256)
        bit_diff = sum(b1 != b2 for b1, b2 in zip(base_bits, mod_bits))
        avalanche_diffs.append(bit_diff)

    # Results
    print(f"\nCollisions found: {collisions}")
    print(f"Avalanche bit differences (sample): {avalanche_diffs[:5]}")

    # Uniformity Plot
    plt.bar(range(num_buckets), buckets)
    plt.title("Hash Output Distribution (Uniformity)")
    plt.xlabel("Bucket")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("uniformity_distribution.png")
    plt.close()

    # Avalanche Boxplot
    plt.boxplot(avalanche_diffs)
    plt.title("Avalanche Effect - Bit Differences")
    plt.ylabel("Bit Differences")
    plt.grid(True)
    plt.savefig("avalanche_boxplot.png")
    plt.close()

if __name__ == "__main__":
    run_all_tests(num_samples=100000)
