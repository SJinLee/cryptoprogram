
'''
Unit tests for the DES algorithm implementation.
'''

import unittest
from des_logic import generate_round_keys, encrypt, decrypt

class TestDES(unittest.TestCase):

    def test_self_consistency(self):
        """Tests if encrypting and then decrypting yields the original plaintext."""
        # A sample 64-bit key and plaintext
        key_str = '0001001100110100010101110111100110011011101111001101111111110001'
        plaintext_str = '0000000100100011010001010110011110001001101010111100110111101111'

        print(f"Original Plaintext: {plaintext_str}")

        # 1. Generate round keys
        round_keys = generate_round_keys(key_str)

        # 2. Encrypt the plaintext
        ciphertext_str = encrypt(plaintext_str, round_keys)
        print(f"Ciphertext:         {ciphertext_str}")

        # 3. Decrypt the ciphertext
        decrypted_str = decrypt(ciphertext_str, round_keys)
        print(f"Decrypted Plaintext:  {decrypted_str}")

        # 4. Assert that the decrypted text matches the original plaintext
        self.assertEqual(plaintext_str, decrypted_str)
        print("\nSuccess: Decrypted text matches original plaintext.")

if __name__ == '__main__':
    unittest.main()

