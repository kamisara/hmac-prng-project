from hmac_prng import HMAC_DRBG

prng = HMAC_DRBG()

# Generate 1000 random numbers and check distribution
numbers = [prng.randint(1, 10) for _ in range(1000)]

# Count occurrences
from collections import Counter
counts = Counter(numbers)
print("Distribution (should be roughly 100 each):")
for i in range(1, 11):
    print(f"  {i}: {counts[i]}")