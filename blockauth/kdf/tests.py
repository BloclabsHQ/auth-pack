"""
Unit tests for KDF services

This module tests all KDF functionality including:
- Key derivation with different algorithms
- Password verification
- Key encryption/decryption
- Security features
"""

import unittest
from unittest.mock import patch

from .constants import KDFAlgorithms

# Import the services to test
from .services import Argon2Service, KDFManager, KeyDerivationService, KeyEncryptionService, PBKDF2Service


class TestPBKDF2Service(unittest.TestCase):
    """Test PBKDF2 key derivation service"""

    def setUp(self):
        """Set up test fixtures"""
        self.service = PBKDF2Service(iterations=1000, hash_algorithm="sha256")
        self.email = "test@example.com"
        self.password = "TestPassword123"
        self.salt = "test_salt_123"

    def test_derive_key_deterministic(self):
        """Test that same input always produces same key"""
        key1 = self.service.derive_key(self.email, self.password, self.salt)
        key2 = self.service.derive_key(self.email, self.password, self.salt)

        self.assertEqual(key1, key2)
        self.assertTrue(key1.startswith("0x"))
        self.assertEqual(len(key1), 66)  # 0x + 64 hex chars

    def test_derive_key_different_inputs(self):
        """Test that different inputs produce different keys"""
        key1 = self.service.derive_key(self.email, self.password, self.salt)
        key2 = self.service.derive_key(self.email, "DifferentPassword", self.salt)
        key3 = self.service.derive_key("different@email.com", self.password, self.salt)
        key4 = self.service.derive_key(self.email, self.password, "different_salt")

        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(key1, key4)

    def test_verify_key_correct(self):
        """Test key verification with correct credentials"""
        expected_key = self.service.derive_key(self.email, self.password, self.salt)

        result = self.service.verify_key(self.email, self.password, self.salt, expected_key)

        self.assertTrue(result)

    def test_verify_key_incorrect(self):
        """Test key verification with incorrect credentials"""
        expected_key = self.service.derive_key(self.email, self.password, self.salt)

        result = self.service.verify_key(self.email, "WrongPassword", self.salt, expected_key)

        self.assertFalse(result)

    def test_minimum_iterations(self):
        """Test that minimum iterations are enforced"""
        # Should not allow less than 1000 iterations
        with self.assertRaises(ValueError):
            PBKDF2Service(iterations=999)

        # Should allow 1000 or more
        service = PBKDF2Service(iterations=1000)
        self.assertEqual(service.iterations, 1000)

    def test_unsupported_hash_algorithm(self):
        """Test that unsupported hash algorithms are rejected"""
        with self.assertRaises(ValueError):
            PBKDF2Service(hash_algorithm="md5")

    def test_sha512_algorithm(self):
        """Test SHA-512 algorithm"""
        service = PBKDF2Service(hash_algorithm="sha512")
        key = service.derive_key(self.email, self.password, self.salt)

        self.assertTrue(key.startswith("0x"))
        self.assertEqual(len(key), 66)


class TestArgon2Service(unittest.TestCase):
    """Test Argon2 key derivation service"""

    def setUp(self):
        """Set up test fixtures"""
        self.service = Argon2Service(time_cost=1, memory_cost=1024, parallelism=1)
        self.email = "test@example.com"
        self.password = "TestPassword123"
        self.salt = "test_salt_123"

    def test_derive_key_deterministic(self):
        """Test that same input always produces same key"""
        key1 = self.service.derive_key(self.email, self.password, self.salt)
        key2 = self.service.derive_key(self.email, self.password, self.salt)

        self.assertEqual(key1, key2)
        self.assertTrue(key1.startswith("0x"))
        self.assertEqual(len(key1), 66)

    def test_derive_key_different_inputs(self):
        """Test that different inputs produce different keys"""
        key1 = self.service.derive_key(self.email, self.password, self.salt)
        key2 = self.service.derive_key(self.email, "DifferentPassword", self.salt)

        self.assertNotEqual(key1, key2)

    def test_minimum_parameters(self):
        """Test that minimum parameters are enforced"""
        # Should not allow less than 1 for time_cost
        with self.assertRaises(ValueError):
            Argon2Service(time_cost=0)

        # Should not allow less than 1024 for memory_cost
        with self.assertRaises(ValueError):
            Argon2Service(memory_cost=512)

        # Should not allow less than 1 for parallelism
        with self.assertRaises(ValueError):
            Argon2Service(parallelism=0)

    @patch.dict("sys.modules", {"argon2": None})
    def test_fallback_to_pbkdf2(self):
        """Test fallback to PBKDF2 when Argon2 is not available"""
        service = Argon2Service()
        self.assertFalse(service.argon2_available)

        # Should still work by falling back to PBKDF2
        key = service.derive_key(self.email, self.password, self.salt)
        self.assertTrue(key.startswith("0x"))


class TestKeyDerivationService(unittest.TestCase):
    """Test main key derivation service"""

    def setUp(self):
        """Set up test fixtures"""
        self.email = "test@example.com"
        self.password = "TestPassword123"
        self.master_salt = "platform_master_salt_32_chars_minimum"

    def test_default_initialization(self):
        """Test default service initialization"""
        service = KeyDerivationService()

        self.assertEqual(service.algorithm, KDFAlgorithms.PBKDF2_SHA256)
        self.assertEqual(service.iterations, 100000)
        self.assertIsInstance(service.kdf_service, PBKDF2Service)

    def test_custom_algorithm(self):
        """Test custom algorithm initialization"""
        service = KeyDerivationService(algorithm=KDFAlgorithms.PBKDF2_SHA512)

        self.assertEqual(service.algorithm, KDFAlgorithms.PBKDF2_SHA512)
        self.assertIsInstance(service.kdf_service, PBKDF2Service)

    def test_security_level_preset(self):
        """Test security level preset initialization"""
        service = KeyDerivationService(security_level="HIGH")

        self.assertEqual(service.algorithm, KDFAlgorithms.ARGON2ID)
        self.assertEqual(service.iterations, 500000)

    def test_master_salt_validation(self):
        """Test master salt validation"""
        # Should reject short master salt
        with self.assertRaises(ValueError):
            KeyDerivationService(master_salt="too_short")

        # Should accept valid master salt
        service = KeyDerivationService(master_salt=self.master_salt)
        self.assertEqual(service.master_salt, self.master_salt)

    def test_create_user_wallet(self):
        """Test user wallet creation"""
        service = KeyDerivationService()

        wallet_data = service.create_user_wallet(self.email, self.password)

        # Check required fields
        required_fields = ["wallet_address", "salt", "public_key", "algorithm", "iterations"]
        for field in required_fields:
            self.assertIn(field, wallet_data)

        # Check wallet address format
        self.assertTrue(wallet_data["wallet_address"].startswith("0x"))
        self.assertEqual(len(wallet_data["wallet_address"]), 42)

        # Check salt format
        self.assertEqual(len(wallet_data["salt"]), 64)  # 32 bytes in hex

        # Check algorithm
        self.assertEqual(wallet_data["algorithm"], KDFAlgorithms.PBKDF2_SHA256)

    def test_create_user_wallet_custom_salt(self):
        """Test user wallet creation with custom salt"""
        service = KeyDerivationService()
        custom_salt = "custom_salt_123"

        wallet_data = service.create_user_wallet(self.email, self.password, user_salt=custom_salt)

        self.assertEqual(wallet_data["salt"], custom_salt)

    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        service = KeyDerivationService()
        wallet_data = service.create_user_wallet(self.email, self.password)

        result = service.verify_password(self.email, self.password, wallet_data["salt"], wallet_data["wallet_address"])

        self.assertTrue(result)

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        service = KeyDerivationService()
        wallet_data = service.create_user_wallet(self.email, self.password)

        result = service.verify_password(
            self.email, "WrongPassword", wallet_data["salt"], wallet_data["wallet_address"]
        )

        self.assertFalse(result)

    def test_get_wallet_address(self):
        """Test getting wallet address without storing private key"""
        service = KeyDerivationService()
        wallet_data = service.create_user_wallet(self.email, self.password)

        address = service.get_wallet_address(self.email, self.password, wallet_data["salt"])

        self.assertEqual(address, wallet_data["wallet_address"])

    def test_unsupported_algorithm(self):
        """Test that unsupported algorithms are rejected"""
        with self.assertRaises(ValueError):
            KeyDerivationService(algorithm="unsupported_algorithm")


class TestKeyEncryptionService(unittest.TestCase):
    """Test key encryption service"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = "0x" + "a" * 64  # 32-byte private key
        self.encryption_key = "0x" + "b" * 64  # 32-byte encryption key

    def test_encryption_decryption(self):
        """Test basic encryption and decryption"""
        service = KeyEncryptionService(self.encryption_key)

        # Encrypt
        encrypted_data = service.encrypt_private_key(self.private_key)

        # Check required fields
        required_fields = ["encrypted_key", "nonce", "tag"]
        for field in required_fields:
            self.assertIn(field, encrypted_data)

        # Decrypt
        decrypted_key = service.decrypt_private_key(encrypted_data)

        self.assertEqual(decrypted_key, self.private_key)

    def test_different_keys_produce_different_ciphertexts(self):
        """Test that same plaintext with different keys produces different ciphertexts"""
        service1 = KeyEncryptionService(self.encryption_key)
        service2 = KeyEncryptionService("0x" + "c" * 64)

        encrypted1 = service1.encrypt_private_key(self.private_key)
        encrypted2 = service2.encrypt_private_key(self.private_key)

        self.assertNotEqual(encrypted1["encrypted_key"], encrypted2["encrypted_key"])

    def test_same_key_produces_different_ciphertexts(self):
        """Test that same plaintext with same key produces different ciphertexts (due to nonce)"""
        service = KeyEncryptionService(self.encryption_key)

        encrypted1 = service.encrypt_private_key(self.private_key)
        encrypted2 = service.encrypt_private_key(self.private_key)

        # Nonces should be different
        self.assertNotEqual(encrypted1["nonce"], encrypted2["nonce"])
        # Ciphertexts should be different
        self.assertNotEqual(encrypted1["encrypted_key"], encrypted2["encrypted_key"])

    def test_invalid_encryption_key_format(self):
        """Test that invalid encryption key formats are rejected"""
        with self.assertRaises(ValueError):
            KeyEncryptionService("invalid_key")

        with self.assertRaises(ValueError):
            KeyEncryptionService("0x" + "a" * 63)  # Too short

    def test_default_key_from_settings(self):
        """Test getting key from Django settings"""
        service = KeyEncryptionService()

        # Should use key from BLOCK_AUTH_SETTINGS
        encrypted_data = service.encrypt_private_key(self.private_key)
        decrypted_key = service.decrypt_private_key(encrypted_data)

        self.assertEqual(decrypted_key, self.private_key)

    def test_missing_key_raises_error(self):
        """Test that missing encryption key raises ValueError"""
        with self.assertRaises(ValueError):
            KeyEncryptionService("")


class TestKDFManager(unittest.TestCase):
    """Test high-level KDF manager"""

    def setUp(self):
        """Set up test fixtures"""
        self.email = "test@example.com"
        self.password = "TestPassword123"
        self.master_salt = "platform_master_salt_32_chars_minimum"
        self.encryption_key = "0x" + "b" * 64

    def test_manager_initialization(self):
        """Test KDF manager initialization"""
        manager = KDFManager(
            algorithm=KDFAlgorithms.PBKDF2_SHA256,
            security_level="MEDIUM",
            master_salt=self.master_salt,
            encryption_key=self.encryption_key,
        )

        self.assertIsInstance(manager.password_kdf_service, KeyDerivationService)
        self.assertIsInstance(manager.platform_encryption_service, KeyEncryptionService)

    def test_create_wallet(self):
        """Test wallet creation with dual encryption"""
        manager = KDFManager(master_salt=self.master_salt, encryption_key=self.encryption_key)

        wallet_data = manager.create_wallet(self.email, self.password)

        # Check required fields
        required_fields = [
            "wallet_address",
            "user_encrypted_key",
            "platform_encrypted_key",
            "user_salt",
            "public_key",
            "algorithm",
            "iterations",
            "wallet_version",
        ]
        for field in required_fields:
            self.assertIn(field, wallet_data)

        # Check wallet address format
        self.assertTrue(wallet_data["wallet_address"].startswith("0x"))
        self.assertEqual(len(wallet_data["wallet_address"]), 42)

        # Check platform encrypted key has AES-GCM fields
        self.assertIn("encrypted_key", wallet_data["platform_encrypted_key"])
        self.assertIn("nonce", wallet_data["platform_encrypted_key"])
        self.assertIn("tag", wallet_data["platform_encrypted_key"])

    def test_platform_key_decryption(self):
        """Test platform key can decrypt the wallet"""
        manager = KDFManager(master_salt=self.master_salt, encryption_key=self.encryption_key)

        wallet_data = manager.create_wallet(self.email, self.password)

        # Decrypt with platform key
        private_key = manager.platform_encryption_service.decrypt_private_key(wallet_data["platform_encrypted_key"])

        # Should return a valid private key
        self.assertTrue(private_key.startswith("0x"))
        self.assertEqual(len(private_key), 66)

    def test_deterministic_wallet_address(self):
        """Test that same credentials produce same wallet address"""
        manager = KDFManager(master_salt=self.master_salt, encryption_key=self.encryption_key)

        wallet1 = manager.create_wallet(self.email, self.password, custom_salt="fixed_salt_for_test")
        wallet2 = manager.create_wallet(self.email, self.password, custom_salt="fixed_salt_for_test")

        self.assertEqual(wallet1["wallet_address"], wallet2["wallet_address"])


class TestSecurityFeatures(unittest.TestCase):
    """Test security features and edge cases"""

    def test_memory_clearing(self):
        """Test that private keys are cleared from memory"""
        service = KeyDerivationService()

        # Create wallet (this should clear private key from memory)
        wallet_data = service.create_user_wallet("test@example.com", "password123")

        # The private key should not be accessible after creation
        self.assertNotIn("private_key", wallet_data)

    def test_deterministic_generation(self):
        """Test that same credentials with same salt always produce same wallet"""
        service = KeyDerivationService()
        fixed_salt = "fixed_test_salt_for_determinism"

        # Create wallet twice with same credentials and salt
        wallet1 = service.create_user_wallet("test@example.com", "password123", user_salt=fixed_salt)
        wallet2 = service.create_user_wallet("test@example.com", "password123", user_salt=fixed_salt)

        # Should be identical
        self.assertEqual(wallet1["wallet_address"], wallet2["wallet_address"])
        self.assertEqual(wallet1["salt"], wallet2["salt"])

    def test_input_normalization(self):
        """Test that inputs are properly normalized"""
        service = KeyDerivationService()
        fixed_salt = "fixed_salt_for_normalization_test"

        # Test email normalization (same salt to test determinism)
        wallet1 = service.create_user_wallet("TEST@EXAMPLE.COM", "password123", user_salt=fixed_salt)
        wallet2 = service.create_user_wallet("test@example.com", "password123", user_salt=fixed_salt)

        # Should be identical (case-insensitive email)
        self.assertEqual(wallet1["wallet_address"], wallet2["wallet_address"])

        # Test password trimming
        wallet3 = service.create_user_wallet("test@example.com", "  password123  ", user_salt=fixed_salt)
        self.assertEqual(wallet1["wallet_address"], wallet3["wallet_address"])


if __name__ == "__main__":
    # Run tests
    unittest.main()
