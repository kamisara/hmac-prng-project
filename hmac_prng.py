"""
HMAC-based Deterministic Random Bit Generator (HMAC-DRBG)
Implementation based on NIST SP 800-90A
"""

import hmac
import hashlib
import os
from typing import Optional


class HMAC_DRBG:
    """
    HMAC-DRBG using SHA-256 as specified in NIST SP 800-90A
    """
    
    def __init__(self, seed: Optional[bytes] = None):
        """
        Initialize the HMAC-DRBG with a seed
        
        Args:
            seed: Optional seed bytes. If None, uses os.urandom for security
        """
        self.security_strength = 256  # SHA-256 security strength
        self.outlen = 256  # Output length in bits
        
        if seed is None:
            # Use system entropy for initial seed (32 bytes for SHA-256)
            seed = os.urandom(32)
        
        self._instantiate(seed)
    
    def _hmac(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def _instantiate(self, seed: bytes):
        """Initialize internal state (K and V)"""
        # K = 0x00...00 (outlen bits)
        self.K = bytes([0] * 32)  # 32 bytes = 256 bits
        
        # V = 0x01...01 (outlen bits)
        self.V = bytes([1] * 32)
        
        # Update K and V with seed
        self._update(seed)
        
        self.reseed_counter = 1
    
    def _update(self, provided_data: bytes):
        """
        Update internal state K and V using provided_data
        """
        # K = HMAC(K, V || 0x00 || provided_data)
        self.K = self._hmac(self.K, self.V + bytes([0]) + provided_data)
        
        # V = HMAC(K, V)
        self.V = self._hmac(self.K, self.V)
        
        # If more data provided, update again
        if provided_data:
            # K = HMAC(K, V || 0x01 || provided_data)
            self.K = self._hmac(self.K, self.V + bytes([1]) + provided_data)
            
            # V = HMAC(K, V)
            self.V = self._hmac(self.K, self.V)
    
    def reseed(self, additional_input: Optional[bytes] = None):
        """
        Reseed the generator with new entropy
        """
        if additional_input is None:
            additional_input = b''
        
        # Get fresh entropy from system
        entropy = os.urandom(32)
        
        # Update with entropy and additional input
        seed_material = entropy + additional_input
        self._update(seed_material)
        
        self.reseed_counter = 1
    
    def generate(self, num_bytes: int, additional_input: Optional[bytes] = None) -> bytes:
        """
        Generate random bytes
        
        Args:
            num_bytes: Number of random bytes to generate
            additional_input: Optional additional input for personalization
        
        Returns:
            Random bytes
        """
        if num_bytes > 7500:  # Maximum request size per NIST
            raise ValueError("Requested too many bytes. Maximum is 7500.")
        
        if self.reseed_counter > 1000000:  # Reseed after 1M requests
            raise RuntimeError("Reseed required")
        
        if additional_input is not None and additional_input:
            self._update(additional_input)
        
        # Generate output
        temp = b''
        while len(temp) < num_bytes:
            self.V = self._hmac(self.K, self.V)
            temp += self.V
        
        # Truncate to requested length
        returned_bits = temp[:num_bytes]
        
        # Update internal state
        self._update(additional_input if additional_input else b'')
        
        self.reseed_counter += 1
        
        return returned_bits
    
    def random(self) -> float:
        """
        Generate random float in range [0.0, 1.0)
        Similar to random.random()
        """
        # Generate 7 bytes (56 bits) for precision
        bytes_7 = self.generate(7)
        
        # Convert to integer and normalize
        int_val = int.from_bytes(bytes_7, 'big')
        max_val = 2 ** 56
        
        return int_val / max_val
    
    def randint(self, a: int, b: int) -> int:
        """
        Generate random integer in range [a, b] inclusive
        """
        if a > b:
            raise ValueError("a must be <= b")
        
        range_size = b - a + 1
        
        # Calculate bytes needed
        num_bits = (range_size - 1).bit_length()
        num_bytes = (num_bits + 7) // 8
        
        # Generate with rejection sampling for uniform distribution
        while True:
            random_bytes = self.generate(num_bytes)
            random_int = int.from_bytes(random_bytes, 'big')
            
            # Rejection sampling to avoid modulo bias
            if random_int < (256 ** num_bytes - (256 ** num_bytes % range_size)):
                return a + (random_int % range_size)
    
    def choice(self, seq):
        """Choose random element from sequence"""
        if not seq:
            raise IndexError("Cannot choose from empty sequence")
        return seq[self.randint(0, len(seq) - 1)]
    
    def shuffle(self, seq):
        """
        Shuffle sequence in-place (Fisher-Yates algorithm)
        """
        for i in range(len(seq) - 1, 0, -1):
            j = self.randint(0, i)
            seq[i], seq[j] = seq[j], seq[i]


def demo():
    """Demonstration of HMAC-DRBG usage"""
    print("=" * 50)
    print("HMAC-DRBG Demonstration")
    print("=" * 50)
    
    # Initialize generator
    prng = HMAC_DRBG()
    
    print("\n1. Generate 32 random bytes:")
    random_bytes = prng.generate(32)
    print(f"   Hex: {random_bytes.hex()}")
    
    print("\n2. Generate random float [0.0, 1.0):")
    print(f"   {prng.random()}")
    print(f"   {prng.random()}")
    
    print("\n3. Generate random integers [1, 100]:")
    for _ in range(5):
        print(f"   {prng.randint(1, 100)}")
    
    print("\n4. Random choice from list:")
    colors = ['red', 'green', 'blue', 'yellow', 'purple']
    print(f"   Chose: {prng.choice(colors)}")
    
    print("\n5. Shuffle list:")
    numbers = list(range(1, 11))
    print(f"   Before: {numbers}")
    prng.shuffle(numbers)
    print(f"   After:  {numbers}")
    
    print("\n6. Reseed and generate again:")
    prng.reseed()
    print(f"   New random bytes: {prng.generate(16).hex()}")
    
    print("\n" + "=" * 50)
    print("All operations completed successfully!")
    print("=" * 50)


if __name__ == "__main__":
    demo()