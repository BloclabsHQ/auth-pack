"""
Security-Focused Tests

Tests specifically for security features:
- IP address validation
- Audit trail decorator
- Encryption requirements
- Input sanitization
"""
import unittest
from unittest.mock import MagicMock, Mock, patch
from datetime import datetime

from blockauth.utils.rate_limiter import get_client_ip, validate_ip_address
from blockauth.utils.audit import audit_trail, _is_sensitive, _sanitize_value


# =============================================================================
# IP Address Validation Tests
# =============================================================================

class TestIPAddressValidation(unittest.TestCase):
    """Test IP address validation security."""

    def test_valid_ipv4_address(self):
        """Valid IPv4 addresses should be accepted."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1",
        ]
        for ip in valid_ips:
            result = validate_ip_address(ip)
            self.assertEqual(result, ip, f"Failed for {ip}")

    def test_valid_ipv6_address(self):
        """Valid IPv6 addresses should be accepted."""
        valid_ips = [
            "::1",
            "2001:db8::1",
            "fe80::1",
        ]
        for ip in valid_ips:
            result = validate_ip_address(ip)
            self.assertIsNotNone(result, f"Failed for {ip}")

    def test_invalid_ip_rejected(self):
        """Invalid IP addresses should be rejected."""
        invalid_ips = [
            "256.256.256.256",
            "not-an-ip",
            "192.168.1",
            "192.168.1.1.1",
            "",
            None,
        ]
        for ip in invalid_ips:
            result = validate_ip_address(ip)
            self.assertIsNone(result, f"Should have rejected {ip}")

    def test_injection_attempt_rejected(self):
        """Injection attempts in IP should be rejected."""
        injection_attempts = [
            "127.0.0.1; rm -rf /",
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1 && whoami",
            "127.0.0.1\nX-Injected: header",
            "127.0.0.1\x00malicious",
        ]
        for ip in injection_attempts:
            result = validate_ip_address(ip)
            self.assertIsNone(result, f"Should have rejected {ip}")

    def test_unspecified_address_rejected(self):
        """Unspecified addresses (0.0.0.0, ::) should be rejected."""
        result = validate_ip_address("0.0.0.0")
        self.assertIsNone(result)

    def test_ip_length_limit(self):
        """Overly long IPs should be rejected."""
        long_ip = "192.168.1.1" + "x" * 100
        result = validate_ip_address(long_ip)
        self.assertIsNone(result)


class TestGetClientIP(unittest.TestCase):
    """Test client IP extraction from request."""

    def _make_request(self, remote_addr=None, x_forwarded_for=None):
        """Create mock request object."""
        request = MagicMock()
        request.META = {}
        if remote_addr:
            request.META['REMOTE_ADDR'] = remote_addr
        if x_forwarded_for:
            request.META['HTTP_X_FORWARDED_FOR'] = x_forwarded_for
        return request

    def test_extracts_remote_addr(self):
        """Should extract IP from REMOTE_ADDR."""
        request = self._make_request(remote_addr="192.168.1.1")
        result = get_client_ip(request)
        self.assertEqual(result, "192.168.1.1")

    def test_prefers_x_forwarded_for(self):
        """Should prefer X-Forwarded-For over REMOTE_ADDR."""
        request = self._make_request(
            remote_addr="10.0.0.1",
            x_forwarded_for="203.0.113.1"
        )
        result = get_client_ip(request)
        self.assertEqual(result, "203.0.113.1")

    def test_handles_multiple_forwarded_ips(self):
        """Should extract first IP from X-Forwarded-For chain."""
        request = self._make_request(
            x_forwarded_for="203.0.113.1, 198.51.100.1, 192.0.2.1"
        )
        result = get_client_ip(request)
        self.assertEqual(result, "203.0.113.1")

    def test_validates_forwarded_ip(self):
        """Should validate X-Forwarded-For IP."""
        request = self._make_request(
            remote_addr="10.0.0.1",
            x_forwarded_for="invalid-ip"
        )
        result = get_client_ip(request)
        self.assertEqual(result, "10.0.0.1")  # Falls back to REMOTE_ADDR

    def test_returns_empty_on_no_valid_ip(self):
        """Should return empty string if no valid IP found."""
        request = self._make_request()
        result = get_client_ip(request)
        self.assertEqual(result, "")

    def test_handles_long_header(self):
        """Should handle overly long X-Forwarded-For header."""
        long_header = "192.168.1.1, " * 100
        request = self._make_request(x_forwarded_for=long_header)
        # Should not raise, should return a valid IP or empty
        result = get_client_ip(request)
        self.assertIsInstance(result, str)


# =============================================================================
# Audit Trail Tests
# =============================================================================

class TestAuditTrailDecorator(unittest.TestCase):
    """Test audit trail decorator functionality."""

    def test_sensitive_param_detection(self):
        """Sensitive parameter names should be detected."""
        sensitive = ['password', 'token', 'secret', 'key', 'private_key', 'backup_code']
        for param in sensitive:
            self.assertTrue(_is_sensitive(param), f"{param} should be sensitive")

    def test_non_sensitive_param_detection(self):
        """Non-sensitive parameter names should not be flagged."""
        non_sensitive = ['user_id', 'email', 'name', 'status', 'count']
        for param in non_sensitive:
            self.assertFalse(_is_sensitive(param), f"{param} should not be sensitive")

    def test_value_sanitization_truncates(self):
        """Long values should be truncated."""
        long_value = "x" * 200
        result = _sanitize_value(long_value, max_length=100)
        self.assertEqual(len(result), 103)  # 100 + "..."
        self.assertTrue(result.endswith("..."))

    def test_value_sanitization_handles_exceptions(self):
        """Unserializable values should be handled."""
        class Unserializable:
            def __str__(self):
                raise Exception("Cannot serialize")

        result = _sanitize_value(Unserializable())
        self.assertEqual(result, "[UNSERIALIZABLE]")

    @patch('blockauth.utils.audit.blockauth_logger')
    def test_decorator_logs_function_call(self, mock_logger):
        """Decorator should log function calls."""
        @audit_trail(event_type="test.event")
        def test_function(user_id):
            return "success"

        result = test_function("user123")

        self.assertEqual(result, "success")
        mock_logger.info.assert_called()

    @patch('blockauth.utils.audit.blockauth_logger')
    def test_decorator_logs_success(self, mock_logger):
        """Decorator should log successful completion."""
        @audit_trail(event_type="test.event")
        def test_function():
            return "success"

        test_function()

        mock_logger.success.assert_called()

    @patch('blockauth.utils.audit.blockauth_logger')
    def test_decorator_logs_failure(self, mock_logger):
        """Decorator should log failures."""
        @audit_trail(event_type="test.event")
        def test_function():
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            test_function()

        # Should have logged warning or error
        self.assertTrue(
            mock_logger.warning.called or mock_logger.error.called
        )

    @patch('blockauth.utils.audit.blockauth_logger')
    def test_decorator_redacts_sensitive_args(self, mock_logger):
        """Decorator should redact sensitive arguments."""
        @audit_trail(event_type="test.event", log_args=True)
        def test_function(user_id, password, secret):
            return "success"

        test_function("user123", "secret_pass", "secret_key")

        # Check that the logged data has redacted values
        call_args = mock_logger.info.call_args
        logged_data = call_args[0][1] if call_args else {}

        if 'arguments' in logged_data:
            args = logged_data['arguments']
            self.assertEqual(args.get('password'), '[REDACTED]')
            self.assertEqual(args.get('secret'), '[REDACTED]')
            self.assertNotEqual(args.get('user_id'), '[REDACTED]')

    def test_decorator_preserves_function_metadata(self):
        """Decorator should preserve function name and docstring."""
        @audit_trail(event_type="test.event")
        def test_function():
            """Test docstring."""
            pass

        self.assertEqual(test_function.__name__, "test_function")
        self.assertEqual(test_function.__doc__, "Test docstring.")


# =============================================================================
# Encryption Requirement Tests
# =============================================================================

class TestEncryptionSecurity(unittest.TestCase):
    """Test encryption security requirements."""

    def test_totp_encryption_required_error_exists(self):
        """TOTPEncryptionRequiredError should exist."""
        from blockauth.totp.exceptions import TOTPEncryptionRequiredError
        error = TOTPEncryptionRequiredError("Test")
        self.assertIsNotNone(error)

    def test_encryption_required_has_error_code(self):
        """Encryption required error should have proper code."""
        from blockauth.totp.exceptions import TOTPEncryptionRequiredError
        from blockauth.totp.constants import TOTPErrorCodes

        self.assertEqual(
            TOTPEncryptionRequiredError.error_code,
            TOTPErrorCodes.ENCRYPTION_REQUIRED
        )


# =============================================================================
# Secret Length Security Tests
# =============================================================================

class TestSecretLengthSecurity(unittest.TestCase):
    """Test secret length security requirements."""

    def test_default_secret_length_in_constants(self):
        """Default secret length should be 32 bytes in constants."""
        from blockauth.totp.constants import DEFAULTS, TOTPConfigKeys
        self.assertEqual(DEFAULTS[TOTPConfigKeys.SECRET_LENGTH], 32)

    def test_secret_minimum_validation(self):
        """Secret generation should reject lengths below 20 bytes."""
        from blockauth.totp.services.totp_service import TOTPService
        from unittest.mock import MagicMock

        store = MagicMock()
        service = TOTPService(store=store)

        with self.assertRaises(ValueError) as context:
            service.generate_secret(length=16)

        self.assertIn("20 bytes", str(context.exception))


# =============================================================================
# Fernet Encryption Service Tests
# =============================================================================

class TestFernetSecretEncryption(unittest.TestCase):
    """Test Fernet-based encryption service."""

    def test_encryption_requires_master_key(self):
        """Encryption service should require a master key."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        with self.assertRaises(ValueError):
            FernetSecretEncryption(master_key="")

        with self.assertRaises(ValueError):
            FernetSecretEncryption(master_key=None)

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt back to original."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="test-master-key-12345")
        original = "JBSWY3DPEHPK3PXP"

        encrypted = encryption.encrypt(original)
        decrypted = encryption.decrypt(encrypted)

        self.assertEqual(decrypted, original)
        self.assertNotEqual(encrypted, original)

    def test_encrypted_data_is_different_each_time(self):
        """Encryption should use random IV, producing different ciphertext."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="test-master-key-12345")
        original = "JBSWY3DPEHPK3PXP"

        encrypted1 = encryption.encrypt(original)
        encrypted2 = encryption.encrypt(original)

        # Same plaintext should produce different ciphertext (random IV)
        self.assertNotEqual(encrypted1, encrypted2)

        # Both should decrypt to the same original
        self.assertEqual(encryption.decrypt(encrypted1), original)
        self.assertEqual(encryption.decrypt(encrypted2), original)

    def test_wrong_key_fails_decryption(self):
        """Decryption with wrong key should fail."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption1 = FernetSecretEncryption(master_key="key-one-12345")
        encryption2 = FernetSecretEncryption(master_key="key-two-12345")

        encrypted = encryption1.encrypt("secret-data")

        with self.assertRaises(ValueError) as context:
            encryption2.decrypt(encrypted)

        self.assertIn("invalid token", str(context.exception))

    def test_encrypt_empty_string_fails(self):
        """Encrypting empty string should fail."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="test-master-key-12345")

        with self.assertRaises(ValueError):
            encryption.encrypt("")

    def test_decrypt_empty_string_fails(self):
        """Decrypting empty string should fail."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="test-master-key-12345")

        with self.assertRaises(ValueError):
            encryption.decrypt("")

    def test_decrypt_corrupted_data_fails(self):
        """Decrypting corrupted data should fail."""
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="test-master-key-12345")

        with self.assertRaises(ValueError):
            encryption.decrypt("not-valid-encrypted-data")

    def test_valid_fernet_key_works(self):
        """Pre-generated valid Fernet key should work directly."""
        from blockauth.totp.services.encryption import FernetSecretEncryption
        from cryptography.fernet import Fernet

        # Generate a valid Fernet key
        valid_key = Fernet.generate_key().decode()

        encryption = FernetSecretEncryption(master_key=valid_key)
        original = "test-secret"

        encrypted = encryption.encrypt(original)
        decrypted = encryption.decrypt(encrypted)

        self.assertEqual(decrypted, original)


class TestGetEncryptionService(unittest.TestCase):
    """Test encryption service factory function."""

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_raises_error_when_key_not_configured(self, mock_settings):
        """Should raise error when encryption key is not configured."""
        from blockauth.totp.services.encryption import (
            get_encryption_service,
            TOTPEncryptionNotConfiguredError
        )

        mock_settings.get.return_value = None

        with self.assertRaises(TOTPEncryptionNotConfiguredError) as context:
            get_encryption_service()

        self.assertIn("TOTP_ENCRYPTION_KEY", str(context.exception))

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_returns_none_when_key_not_configured_and_not_raising(self, mock_settings):
        """Should return None when key not configured and raise_if_missing=False."""
        from blockauth.totp.services.encryption import get_encryption_service

        mock_settings.get.return_value = None

        result = get_encryption_service(raise_if_missing=False)

        self.assertIsNone(result)

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_returns_service_when_key_configured(self, mock_settings):
        """Should return encryption service when key is configured."""
        from blockauth.totp.services.encryption import get_encryption_service, FernetSecretEncryption

        mock_settings.get.return_value = "test-encryption-key-12345"

        result = get_encryption_service()

        self.assertIsInstance(result, FernetSecretEncryption)


class TestValidateTOTPEncryptionConfig(unittest.TestCase):
    """Test TOTP encryption configuration validation."""

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_passes_when_totp_disabled(self, mock_settings):
        """Should pass validation when TOTP is disabled."""
        from blockauth.totp.services.encryption import validate_totp_encryption_config
        from blockauth.totp.constants import TOTPConfigKeys

        mock_settings.get.side_effect = lambda key, default=None: {
            TOTPConfigKeys.ENABLED: False,
        }.get(key, default)

        result = validate_totp_encryption_config()
        self.assertTrue(result)

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_fails_when_totp_enabled_without_key(self, mock_settings):
        """Should fail when TOTP enabled but no encryption key."""
        from blockauth.totp.services.encryption import (
            validate_totp_encryption_config,
            TOTPEncryptionNotConfiguredError
        )
        from blockauth.totp.constants import TOTPConfigKeys

        mock_settings.get.side_effect = lambda key, default=None: {
            TOTPConfigKeys.ENABLED: True,
            TOTPConfigKeys.ENCRYPTION_KEY: None,
        }.get(key, default)

        with self.assertRaises(TOTPEncryptionNotConfiguredError):
            validate_totp_encryption_config()

    @patch('blockauth.totp.services.encryption.blockauth_settings')
    def test_passes_when_totp_enabled_with_valid_key(self, mock_settings):
        """Should pass when TOTP enabled with valid encryption key."""
        from blockauth.totp.services.encryption import validate_totp_encryption_config
        from blockauth.totp.constants import TOTPConfigKeys

        mock_settings.get.side_effect = lambda key, default=None: {
            TOTPConfigKeys.ENABLED: True,
            TOTPConfigKeys.ENCRYPTION_KEY: "valid-test-encryption-key-12345",
        }.get(key, default)

        result = validate_totp_encryption_config()
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
