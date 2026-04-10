"""
Comprehensive TOTP Service Tests

Security-focused test suite covering:
- TOTP generation/verification edge cases
- Rate limiting behavior
- Backup code functionality
- Replay attack prevention
- Error conditions and exception handling
- Encryption requirements
- Secret length requirements

Per SECURITY_STANDARDS.md requirements.
"""

import time
import unittest
from datetime import datetime

from ..constants import DEFAULTS, TOTPAlgorithm, TOTPErrorCodes, TOTPStatus
from ..exceptions import (
    TOTPAccountLockedError,
    TOTPAlreadyEnabledError,
    TOTPBackupCodeUsedError,
    TOTPCodeReusedError,
    TOTPEncryptionRequiredError,
    TOTPError,
    TOTPInvalidBackupCodeError,
    TOTPInvalidCodeError,
    TOTPNotEnabledError,
    TOTPSetupError,
    TOTPTooManyAttemptsError,
    TOTPVerificationError,
)
from ..services.totp_service import SetupResult, TOTPService
from ..storage.base import ITOTP2FAStore, TOTP2FAData


class MockTOTPStore(ITOTP2FAStore):
    """Mock storage for testing."""

    def __init__(self):
        self.data = {}
        self.backup_codes = {}
        self.used_codes = {}
        self.failed_attempts = {}

    def get_by_user_id(self, user_id: str):
        return self.data.get(user_id)

    def create(self, user_id: str, encrypted_secret: str, algorithm: str, digits: int, time_step: int, status: str):
        self.data[user_id] = TOTP2FAData(
            user_id=user_id,
            encrypted_secret=encrypted_secret,
            algorithm=algorithm,
            digits=digits,
            time_step=time_step,
            status=status,
            backup_codes_remaining=0,
            failed_attempts=0,
            locked_until=None,
            enabled_at=None,
        )
        return self.data[user_id]

    def update(self, user_id: str, **kwargs):
        if user_id in self.data:
            data = self.data[user_id]
            for key, value in kwargs.items():
                if hasattr(data, key):
                    object.__setattr__(data, key, value)
        return self.data.get(user_id)

    def delete(self, user_id: str) -> bool:
        if user_id in self.data:
            del self.data[user_id]
            return True
        return False

    def get_backup_codes(self, user_id: str) -> list:
        return self.backup_codes.get(user_id, [])

    def update_status(self, user_id: str, status: str) -> bool:
        if user_id in self.data:
            self.update(user_id, status=status)
            return True
        return False

    def set_backup_codes(self, user_id: str, hashed_codes: list):
        self.backup_codes[user_id] = hashed_codes
        if user_id in self.data:
            self.update(user_id, backup_codes_remaining=len(hashed_codes), backup_codes_hash=list(hashed_codes))

    def use_backup_code(self, user_id: str, code_index: int) -> bool:
        data = self.data.get(user_id)
        if data and 0 <= code_index < len(data.backup_codes_hash):
            new_codes = list(data.backup_codes_hash)
            new_codes[code_index] = None
            remaining = sum(1 for c in new_codes if c)
            self.update(user_id, backup_codes_hash=new_codes, backup_codes_remaining=remaining)
            return True
        return False

    def record_failed_attempt(self, user_id: str, max_attempts: int = 5, lockout_duration: int = 300) -> bool:
        from datetime import timedelta, timezone
        data = self.data.get(user_id)
        if data:
            new_count = data.failed_attempts + 1
            self.update(user_id, failed_attempts=new_count)
            if new_count >= max_attempts:
                locked_until = datetime.now(tz=timezone.utc) + timedelta(seconds=lockout_duration)
                self.update(user_id, locked_until=locked_until)
                return True
        return False

    def record_successful_verification(self, user_id: str, time_counter: int) -> bool:
        if user_id in self.data:
            self.update(user_id, last_used_counter=time_counter, failed_attempts=0)
            self.used_codes[user_id] = time_counter
            return True
        return False

    def is_counter_used(self, user_id: str, time_counter: int) -> bool:
        data = self.data.get(user_id)
        if data is None:
            return False
        return getattr(data, "last_used_counter", None) == time_counter

    def log_verification(
        self,
        user_id: str,
        success: bool,
        verification_type: str = "totp",
        ip_address=None,
        user_agent: str = "",
        failure_reason: str = "",
    ) -> None:
        pass

    def reset_failed_attempts(self, user_id: str):
        self.update(user_id, failed_attempts=0)

    def lock_account(self, user_id: str, until: datetime):
        self.update(user_id, locked_until=until)

    def unlock_account(self, user_id: str):
        self.update(user_id, locked_until=None, failed_attempts=0)

    def get_last_used_code(self, user_id: str):
        return self.used_codes.get(user_id)


class MockEncryption:
    """Mock encryption service."""

    def encrypt(self, data: str) -> str:
        return f"encrypted:{data}"

    def decrypt(self, data: str) -> str:
        if data.startswith("encrypted:"):
            return data[10:]
        return data


# =============================================================================
# TOTP Generation Tests
# =============================================================================


class TestTOTPSecretGeneration(unittest.TestCase):
    """Test TOTP secret generation security requirements."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def test_default_secret_length_is_256_bits(self):
        """SECURITY: Default secret length must be 32 bytes (256 bits)."""
        secret = self.service.generate_secret()
        # Base32 encoding: 32 bytes -> 52 chars (without padding)
        self.assertGreaterEqual(len(secret), 51)

    def test_secret_minimum_length_enforced(self):
        """SECURITY: Secret length below 20 bytes must be rejected."""
        with self.assertRaises(ValueError) as context:
            self.service.generate_secret(length=16)
        self.assertIn("20 bytes", str(context.exception))

    def test_secret_is_base32_encoded(self):
        """Secret must be valid Base32."""
        secret = self.service.generate_secret()
        # Base32 alphabet: A-Z, 2-7
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        self.assertTrue(all(c in valid_chars for c in secret))

    def test_secrets_are_unique(self):
        """Each generated secret must be unique."""
        secrets = [self.service.generate_secret() for _ in range(100)]
        self.assertEqual(len(secrets), len(set(secrets)))

    def test_custom_secret_length(self):
        """Custom secret lengths above minimum should work."""
        secret = self.service.generate_secret(length=64)
        # 64 bytes -> ~103 base32 chars
        self.assertGreaterEqual(len(secret), 100)


# =============================================================================
# Encryption Requirement Tests
# =============================================================================


class TestEncryptionRequirements(unittest.TestCase):
    """Test that encryption is mandatory for secret storage."""

    def setUp(self):
        self.store = MockTOTPStore()

    def test_encrypt_secret_fails_without_encryption_service(self):
        """SECURITY: Must fail if encryption service not configured."""
        service = TOTPService(store=self.store, encryption_service=None)

        with self.assertRaises(TOTPEncryptionRequiredError) as context:
            service._encrypt_secret("test_secret")

        self.assertIn("encryption", str(context.exception).lower())

    def test_decrypt_secret_fails_without_encryption_service(self):
        """SECURITY: Must fail if encryption service not configured."""
        service = TOTPService(store=self.store, encryption_service=None)

        with self.assertRaises(TOTPEncryptionRequiredError) as context:
            service._decrypt_secret("encrypted_data")

        self.assertIn("encryption", str(context.exception).lower())

    def test_setup_fails_without_encryption(self):
        """SECURITY: Setup must fail if encryption not configured."""
        service = TOTPService(store=self.store, encryption_service=None)

        with self.assertRaises(TOTPEncryptionRequiredError):
            service.setup_totp(user_id="user123", account_name="test@example.com")

    def test_secrets_are_encrypted_before_storage(self):
        """Secrets must be encrypted before storage."""
        encryption = MockEncryption()
        service = TOTPService(store=self.store, encryption_service=encryption)

        service.setup_totp(user_id="user123", account_name="test@example.com")

        stored_data = self.store.get_by_user_id("user123")
        self.assertTrue(stored_data.encrypted_secret.startswith("encrypted:"))


# =============================================================================
# TOTP Verification Tests
# =============================================================================


class TestTOTPVerification(unittest.TestCase):
    """Test TOTP code verification."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def _setup_enabled_totp(self, user_id: str = "user123") -> str:
        """Helper to set up enabled TOTP and return the secret."""
        result = self.service.setup_totp(user_id=user_id, account_name="test@example.com")
        secret = result.secret

        # Generate valid code and confirm
        code = self.service.generate_code(secret)
        self.service.confirm_setup(user_id, code)

        return secret

    def test_valid_code_verification(self):
        """Valid TOTP code should verify successfully."""
        secret = self._setup_enabled_totp()
        code = self.service.generate_code(secret)

        result = self.service.verify(user_id="user123", code=code)

        self.assertTrue(result.success)
        self.assertEqual(result.verification_type, "totp")

    def test_invalid_code_rejection(self):
        """Invalid TOTP code should be rejected."""
        self._setup_enabled_totp()

        with self.assertRaises(TOTPInvalidCodeError):
            self.service.verify(user_id="user123", code="000000")

    def test_expired_code_rejection(self):
        """Expired TOTP codes should be rejected."""
        secret = self._setup_enabled_totp()

        # Generate code for a past time window
        past_time = int(time.time()) - 120  # 2 minutes ago
        old_code = self.service.generate_code(secret, timestamp=past_time)

        with self.assertRaises(TOTPInvalidCodeError):
            self.service.verify(user_id="user123", code=old_code)

    def test_window_tolerance(self):
        """Codes within window tolerance should be accepted."""
        secret = self._setup_enabled_totp()

        # Code from one time step ago should work with default window=1
        past_time = int(time.time()) - 30
        code = self.service.generate_code(secret, timestamp=past_time)

        result = self.service.verify(user_id="user123", code=code)
        self.assertTrue(result.success)

    def test_verification_requires_enabled_status(self):
        """Verification should fail if TOTP not enabled."""
        # Setup but don't confirm
        self.service.setup_totp(user_id="user123", account_name="test@example.com")

        with self.assertRaises(TOTPNotEnabledError):
            self.service.verify(user_id="user123", code="123456")

    def test_verification_for_nonexistent_user(self):
        """Verification should fail for unknown user."""
        with self.assertRaises(TOTPNotEnabledError):
            self.service.verify(user_id="unknown", code="123456")


# =============================================================================
# Replay Attack Prevention Tests
# =============================================================================


class TestReplayAttackPrevention(unittest.TestCase):
    """Test replay attack prevention mechanisms."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def _setup_enabled_totp(self, user_id: str = "user123") -> str:
        result = self.service.setup_totp(user_id=user_id, account_name="test@example.com")
        secret = result.secret
        code = self.service.generate_code(secret)
        self.service.confirm_setup(user_id, code)
        return secret

    def test_code_reuse_prevention(self):
        """SECURITY: Same code cannot be used twice."""
        secret = self._setup_enabled_totp()
        code = self.service.generate_code(secret)

        # First use should succeed
        result = self.service.verify(user_id="user123", code=code)
        self.assertTrue(result.success)

        # Second use should fail
        with self.assertRaises(TOTPCodeReusedError):
            self.service.verify(user_id="user123", code=code)

    def test_last_used_code_tracked(self):
        """Last used counter should be stored for replay prevention."""
        secret = self._setup_enabled_totp()
        code = self.service.generate_code(secret)
        _, counter = self.service.generate_totp(secret)

        self.service.verify(user_id="user123", code=code)

        data = self.store.get_by_user_id("user123")
        self.assertIsNotNone(data.last_used_counter)
        self.assertEqual(data.last_used_counter, counter)


# =============================================================================
# Rate Limiting Tests
# =============================================================================


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting and account lockout."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def _setup_enabled_totp(self, user_id: str = "user123") -> str:
        result = self.service.setup_totp(user_id=user_id, account_name="test@example.com")
        secret = result.secret
        code = self.service.generate_code(secret)
        self.service.confirm_setup(user_id, code)
        return secret

    def test_failed_attempts_tracked(self):
        """Failed verification attempts should be tracked."""
        self._setup_enabled_totp()

        for _ in range(3):
            try:
                self.service.verify(user_id="user123", code="000000")
            except TOTPInvalidCodeError:
                pass

        data = self.store.get_by_user_id("user123")
        self.assertEqual(data.failed_attempts, 3)

    def test_account_lockout_after_max_attempts(self):
        """Account should be locked after max failed attempts."""
        self._setup_enabled_totp()
        max_attempts = self.service.config.max_attempts

        # Exhaust all attempts
        for _ in range(max_attempts):
            try:
                self.service.verify(user_id="user123", code="000000")
            except (TOTPInvalidCodeError, TOTPTooManyAttemptsError):
                pass

        # Next attempt should raise locked error
        with self.assertRaises((TOTPTooManyAttemptsError, TOTPAccountLockedError)):
            self.service.verify(user_id="user123", code="000000")

    def test_successful_verification_resets_attempts(self):
        """Successful verification should reset failed attempts."""
        secret = self._setup_enabled_totp()

        # Make some failed attempts
        for _ in range(2):
            try:
                self.service.verify(user_id="user123", code="000000")
            except TOTPInvalidCodeError:
                pass

        # Verify with correct code
        code = self.service.generate_code(secret)
        self.service.verify(user_id="user123", code=code)

        data = self.store.get_by_user_id("user123")
        self.assertEqual(data.failed_attempts, 0)


# =============================================================================
# Backup Code Tests
# =============================================================================


class TestBackupCodes(unittest.TestCase):
    """Test backup code functionality."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def _setup_enabled_totp(self, user_id: str = "user123"):
        result = self.service.setup_totp(user_id=user_id, account_name="test@example.com")
        secret = result.secret
        backup_codes = result.backup_codes
        code = self.service.generate_code(secret)
        self.service.confirm_setup(user_id, code)
        return secret, backup_codes

    def test_backup_codes_generated_on_setup(self):
        """Backup codes should be generated during setup."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")

        self.assertIsNotNone(result.backup_codes)
        self.assertEqual(len(result.backup_codes), self.service.config.backup_codes_count)

    def test_backup_codes_are_unique(self):
        """All backup codes should be unique."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")

        codes = result.backup_codes
        self.assertEqual(len(codes), len(set(codes)))

    def test_backup_code_verification(self):
        """Valid backup code should verify successfully."""
        _, backup_codes = self._setup_enabled_totp()
        backup_code = backup_codes[0]

        result = self.service.verify(user_id="user123", code=backup_code)

        self.assertTrue(result.success)
        self.assertEqual(result.verification_type, "backup_code")

    def test_backup_code_single_use(self):
        """Backup code should only work once."""
        _, backup_codes = self._setup_enabled_totp()
        backup_code = backup_codes[0]

        # First use should succeed
        self.service.verify(user_id="user123", code=backup_code)

        # Second use should fail
        with self.assertRaises((TOTPInvalidBackupCodeError, TOTPBackupCodeUsedError, TOTPInvalidCodeError)):
            self.service.verify(user_id="user123", code=backup_code)

    def test_backup_codes_remaining_decrements(self):
        """Remaining backup codes count should decrement on use."""
        _, backup_codes = self._setup_enabled_totp()
        initial_count = len(backup_codes)

        self.service.verify(user_id="user123", code=backup_codes[0])

        result = self.service.verify(
            user_id="user123",
            code=self.service.generate_code(
                self.encryption.decrypt(self.store.get_by_user_id("user123").encrypted_secret)
            ),
        )
        self.assertEqual(result.backup_codes_remaining, initial_count - 1)

    def test_regenerate_backup_codes(self):
        """Should be able to regenerate backup codes."""
        self._setup_enabled_totp()

        new_codes = self.service.regenerate_backup_codes("user123")

        self.assertEqual(len(new_codes), self.service.config.backup_codes_count)

    def test_regenerate_invalidates_old_codes(self):
        """Regenerating codes should invalidate old ones."""
        _, old_codes = self._setup_enabled_totp()
        old_code = old_codes[0]

        # Regenerate
        self.service.regenerate_backup_codes("user123")

        # Old code should no longer work
        with self.assertRaises((TOTPInvalidBackupCodeError, TOTPInvalidCodeError)):
            self.service.verify(user_id="user123", code=old_code)

    def test_regenerate_requires_enabled_totp(self):
        """Cannot regenerate backup codes if TOTP not enabled."""
        with self.assertRaises(TOTPNotEnabledError):
            self.service.regenerate_backup_codes("unknown_user")


# =============================================================================
# Setup Flow Tests
# =============================================================================


class TestSetupFlow(unittest.TestCase):
    """Test TOTP setup workflow."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def test_setup_returns_required_data(self):
        """Setup should return secret, URI, and backup codes."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")

        self.assertIsInstance(result, SetupResult)
        self.assertIsNotNone(result.secret)
        self.assertIsNotNone(result.provisioning_uri)
        self.assertIsNotNone(result.backup_codes)

    def test_setup_creates_pending_status(self):
        """Setup should create TOTP in pending status."""
        self.service.setup_totp(user_id="user123", account_name="test@example.com")

        data = self.store.get_by_user_id("user123")
        self.assertEqual(data.status, TOTPStatus.PENDING_CONFIRMATION.value)

    def test_confirm_enables_totp(self):
        """Confirm with valid code should enable TOTP."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")
        code = self.service.generate_code(result.secret)

        self.service.confirm_setup("user123", code)

        data = self.store.get_by_user_id("user123")
        self.assertEqual(data.status, TOTPStatus.ENABLED.value)

    def test_confirm_with_invalid_code_fails(self):
        """Confirm with invalid code should fail."""
        self.service.setup_totp(user_id="user123", account_name="test@example.com")

        with self.assertRaises(TOTPInvalidCodeError):
            self.service.confirm_setup("user123", "000000")

    def test_cannot_setup_if_already_enabled(self):
        """Setup should fail if TOTP already enabled."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")
        code = self.service.generate_code(result.secret)
        self.service.confirm_setup("user123", code)

        with self.assertRaises(TOTPAlreadyEnabledError):
            self.service.setup_totp(user_id="user123", account_name="test@example.com")

    def test_provisioning_uri_format(self):
        """Provisioning URI should follow otpauth format."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com", issuer="TestApp")

        uri = result.provisioning_uri
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn("secret=", uri)
        self.assertIn("issuer=", uri)


# =============================================================================
# Disable TOTP Tests
# =============================================================================


class TestDisableTOTP(unittest.TestCase):
    """Test TOTP disable functionality."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def _setup_enabled_totp(self, user_id: str = "user123"):
        result = self.service.setup_totp(user_id=user_id, account_name="test@example.com")
        code = self.service.generate_code(result.secret)
        self.service.confirm_setup(user_id, code)

    def test_disable_removes_totp(self):
        """Disable should remove TOTP configuration."""
        self._setup_enabled_totp()

        result = self.service.disable("user123")

        self.assertTrue(result)
        self.assertIsNone(self.store.get_by_user_id("user123"))

    def test_disable_nonexistent_returns_false(self):
        """Disable for unknown user should return False."""
        result = self.service.disable("unknown_user")
        self.assertFalse(result)


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptions(unittest.TestCase):
    """Test exception classes and error handling."""

    def test_totp_error_base_class(self):
        """TOTPError should be the base exception class."""
        error = TOTPError("Test error")
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Test error")

    def test_totp_error_to_dict(self):
        """Exceptions should serialize to dict properly."""
        error = TOTPInvalidCodeError("Invalid code provided")
        error_dict = error.to_dict()

        self.assertIn("error", error_dict)
        self.assertIn("message", error_dict)

    def test_specific_error_codes(self):
        """Each exception should have correct error code."""
        self.assertEqual(TOTPInvalidCodeError.error_code, TOTPErrorCodes.INVALID_CODE)
        self.assertEqual(TOTPNotEnabledError.error_code, TOTPErrorCodes.NOT_ENABLED)
        self.assertEqual(TOTPAlreadyEnabledError.error_code, TOTPErrorCodes.ALREADY_ENABLED)
        self.assertEqual(TOTPEncryptionRequiredError.error_code, TOTPErrorCodes.ENCRYPTION_REQUIRED)


# =============================================================================
# Constants and Configuration Tests
# =============================================================================


class TestConstants(unittest.TestCase):
    """Test TOTP constants and defaults."""

    def test_default_secret_length_is_256_bits(self):
        """SECURITY: Default secret length must be 32 bytes."""
        self.assertEqual(DEFAULTS["SECRET_LENGTH"], 32)

    def test_supported_algorithms(self):
        """Should support standard TOTP algorithms."""
        self.assertEqual(TOTPAlgorithm.SHA1.value, "sha1")
        self.assertEqual(TOTPAlgorithm.SHA256.value, "sha256")
        self.assertEqual(TOTPAlgorithm.SHA512.value, "sha512")

    def test_status_enum_values(self):
        """Status enum should have expected values."""
        self.assertEqual(TOTPStatus.DISABLED.value, "disabled")
        self.assertEqual(TOTPStatus.PENDING_CONFIRMATION.value, "pending_confirmation")
        self.assertEqual(TOTPStatus.ENABLED.value, "enabled")


# =============================================================================
# Input Validation Tests
# =============================================================================


class TestInputValidation(unittest.TestCase):
    """Test input validation for security."""

    def setUp(self):
        self.store = MockTOTPStore()
        self.encryption = MockEncryption()
        self.service = TOTPService(store=self.store, encryption_service=self.encryption)

    def test_code_length_validation(self):
        """Code should be validated for proper length."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")
        code = self.service.generate_code(result.secret)
        self.service.confirm_setup("user123", code)

        # Too short
        with self.assertRaises((TOTPInvalidCodeError, TOTPVerificationError, TOTPInvalidBackupCodeError)):
            self.service.verify(user_id="user123", code="123")

        # Too long
        with self.assertRaises((TOTPInvalidCodeError, TOTPVerificationError, TOTPInvalidBackupCodeError)):
            self.service.verify(user_id="user123", code="12345678901234567890")

    def test_non_numeric_code_rejected(self):
        """Non-numeric codes should be rejected."""
        result = self.service.setup_totp(user_id="user123", account_name="test@example.com")
        code = self.service.generate_code(result.secret)
        self.service.confirm_setup("user123", code)

        with self.assertRaises((TOTPInvalidCodeError, TOTPVerificationError, TOTPInvalidBackupCodeError)):
            self.service.verify(user_id="user123", code="abcdef")

    def test_empty_user_id_handling(self):
        """Empty user ID should be handled gracefully."""
        with self.assertRaises((ValueError, TOTPSetupError)):
            self.service.setup_totp(user_id="", account_name="test@example.com")


if __name__ == "__main__":
    unittest.main()
