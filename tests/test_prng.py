"""
Unit tests for HMAC-DRBG implementation
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hmac_prng import HMAC_DRBG


class TestHMAC_DRBG(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.prng = HMAC_DRBG(seed=b'test_seed_1234567890123456789012')
    
    def test_generate_bytes(self):
        """Test basic byte generation"""
        data = self.prng.generate(32)
        self.assertEqual(len(data), 32)
        self.assertIsInstance(data, bytes)
    
    def test_generate_different_values(self):
        """Test that consecutive calls produce different values"""
        data1 = self.prng.generate(32)
        data2 = self.prng.generate(32)
        self.assertNotEqual(data1, data2)
    
    def test_deterministic_with_same_seed(self):
        """Test determinism with same seed"""
        prng1 = HMAC_DRBG(seed=b'same_seed_1234567890123456789012')
        prng2 = HMAC_DRBG(seed=b'same_seed_1234567890123456789012')
        
        self.assertEqual(prng1.generate(32), prng2.generate(32))
    
    def test_random_float_range(self):
        """Test that random() returns values in [0.0, 1.0)"""
        for _ in range(100):
            val = self.prng.random()
            self.assertGreaterEqual(val, 0.0)
            self.assertLess(val, 1.0)
    
    def test_randint_range(self):
        """Test randint returns values in correct range"""
        for _ in range(100):
            val = self.prng.randint(1, 10)
            self.assertGreaterEqual(val, 1)
            self.assertLessEqual(val, 10)
    
    def test_randint_edge_cases(self):
        """Test randint with edge cases"""
        # Same value
        self.assertEqual(self.prng.randint(5, 5), 5)
        
        # Negative numbers
        val = self.prng.randint(-10, -1)
        self.assertGreaterEqual(val, -10)
        self.assertLessEqual(val, -1)
    
    def test_choice(self):
        """Test random choice"""
        items = ['a', 'b', 'c', 'd', 'e']
        chosen = self.prng.choice(items)
        self.assertIn(chosen, items)
    
    def test_shuffle(self):
        """Test shuffle"""
        original = list(range(10))
        shuffled = original.copy()
        self.prng.shuffle(shuffled)
        
        # Same elements
        self.assertEqual(sorted(shuffled), original)
        
        # Different order (high probability)
        self.assertNotEqual(shuffled, original)
    
    def test_reseed_changes_output(self):
        """Test that reseed changes the output sequence"""
        prng = HMAC_DRBG(seed=b'seed_for_reseed_test_1234567890')
        
        # Generate some values
        before = [prng.generate(16) for _ in range(5)]
        
        # Reseed
        prng.reseed()
        
        # Generate more values
        after = [prng.generate(16) for _ in range(5)]
        
        # Should be different
        self.assertNotEqual(before[0], after[0])
    
    def test_large_request_fails(self):
        """Test that requesting too many bytes raises error"""
        with self.assertRaises(ValueError):
            self.prng.generate(8000)
    
    def test_empty_sequence_choice(self):
        """Test that choice on empty sequence raises error"""
        with self.assertRaises(IndexError):
            self.prng.choice([])


class TestStatisticalProperties(unittest.TestCase):
    """Basic statistical tests"""
    
    def test_byte_distribution(self):
        """Test that bytes are roughly uniformly distributed"""
        prng = HMAC_DRBG()
        
        # Generate many bytes
        data = prng.generate(10000)
        
        # Count occurrences of each byte value
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        # Check that all values appear (with high probability)
        zeros = counts.count(0)
        self.assertLess(zeros, 10)  # Very few should be missing
        
        # Check rough uniformity (mean should be ~39)
        mean_count = sum(counts) / 256
        self.assertGreater(mean_count, 30)
        self.assertLess(mean_count, 50)


if __name__ == '__main__':
    unittest.main()