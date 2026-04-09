"""
TOTP Service - RFC 6238 Implementation

Implements Time-based One-Time Password (TOTP) algorithm per RFC 6238,
with backup codes, rate limiting, and replay attack prevention.

Security: All sensitive operations are audit logged per SECURITY_STANDARDS.md
"""

import base64
import hashlib
import hmac
import logging
import secrets
import struct
import time
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Tuple

from blockauth.utils.audit import audit_trail

from ..config import TOTPConfiguration, get_totp_config
from ..constants import TOTPAlgorithm, TOTPStatus
from ..exceptions import (
    TOTPAccountLockedError,
    TOTPAlreadyEnabledError,
    TOTPBackupCodeUsedError,
    TOTPCodeReusedError,
    TOTPEncryptionRequiredError,
    TOTPInvalidBackupCodeError,
    TOTPInvalidCodeError,
    TOTPInvalidSecretError,
    TOTPNotEnabledError,
    TOTPSetupError,
    TOTPVerificationError,
)
from ..storage.base import ITOTP2FAStore, TOTP2FAData

logger = logging.getLogger(__name__)


# Algorithm mapping for HMAC
ALGORITHM_MAP = {
    TOTPAlgorithm.SHA1.value: hashlib.sha1,
    TOTPAlgorithm.SHA256.value: hashlib.sha256,
    TOTPAlgorithm.SHA512.value: hashlib.sha512,
}


@dataclass
class SetupResult:
    """Result of TOTP setup operation."""

    secret: str  # Base32-encoded secret (to show to user)
    provisioning_uri: str  # otpauth:// URI for QR code
    backup_codes: List[str]  # Plain text backup codes (show once)


@dataclass
class VerifyResult:
    """Result of TOTP verification."""

    success: bool
    verification_type: str = "totp"  # 'totp' or 'backup'
    backup_codes_remaining: Optional[int] = None


class TOTPService:
    """
    Service for TOTP 2FA operations.

    Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
    with additional features:
    - Backup codes for recovery
    - Rate limiting and lockout
    - Replay attack prevention
    - Audit logging

    Usage:
        from blockauth.totp.services import TOTPService
        from blockauth.totp.storage import DjangoTOTP2FAStore

        store = DjangoTOTP2FAStore()
        service = TOTPService(store)

        # Setup TOTP for user
        result = service.setup_totp(user_id, user_email)
        # Show result.provisioning_uri as QR code
        # Show result.backup_codes (once only)

        # Confirm TOTP setup
        service.confirm_setup(user_id, code_from_app)

        # Verify TOTP during login
        if service.verify(user_id, code):
            # Grant access
    """

    def __init__(
        self,
        store: ITOTP2FAStore,
        config: Optional[TOTPConfiguration] = None,
        encryption_service: Optional["ISecretEncryption"] = None,
    ):
        """
        Initialize TOTP service.

        Args:
            store: Storage backend for TOTP data
            config: TOTP configuration (uses defaults if not provided)
            encryption_service: Optional encryption service for secrets
        """
        self.store = store
        self.config = config or get_totp_config()
        self.encryption = encryption_service

    # =========================================================================
    # Core TOTP Algorithm (RFC 6238)
    # =========================================================================

    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """
        Generate a cryptographically secure TOTP secret.

        Security: Default 32 bytes (256 bits) per SECURITY_STANDARDS.md.
        RFC 4226 minimum is 16 bytes (128 bits), but we enforce 20 bytes
        (160 bits) as the absolute minimum for compatibility while
        defaulting to 256-bit security.

        Args:
            length: Length in bytes (minimum 20, default 32 = 256 bits)

        Returns:
            Base32-encoded secret string

        Raises:
            ValueError: If length is below 20 bytes (160 bits)
        """
        if length < 20:
            raise ValueError(
                "Secret length must be at least 20 bytes (160 bits). "
                "Recommended: 32 bytes (256 bits) for optimal security."
            )

        secret_bytes = secrets.token_bytes(length)
        return base64.b32encode(secret_bytes).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_secret(secret: str) -> bytes:
        """
        Decode a Base32 TOTP secret to bytes.

        Handles secrets with or without padding.

        Args:
            secret: Base32-encoded secret

        Returns:
            Secret as bytes
        """
        # Normalize: uppercase and add padding if needed
        secret = secret.upper().replace(" ", "")
        padding = (8 - len(secret) % 8) % 8
        secret += "=" * padding

        try:
            return base64.b32decode(secret)
        except Exception as e:
            raise TOTPInvalidSecretError(f"Invalid TOTP secret format: {e}")

    @classmethod
    def generate_totp(
        cls, secret: str, time_offset: int = 0, time_step: int = 30, digits: int = 6, algorithm: str = "sha1"
    ) -> Tuple[str, int]:
        """
        Generate a TOTP code from a secret.

        Implements RFC 6238 algorithm.

        Args:
            secret: Base32-encoded TOTP secret
            time_offset: Time offset in seconds (for testing/time skew)
            time_step: Time step in seconds (default 30)
            digits: Number of digits in code (6 or 8)
            algorithm: Hash algorithm (sha1, sha256, sha512)

        Returns:
            Tuple of (TOTP code, time counter used)
        """
        secret_bytes = cls._decode_secret(secret)

        # Get hash function
        hash_func = ALGORITHM_MAP.get(algorithm, hashlib.sha1)

        # Calculate time counter (T = floor((current_time - T0) / time_step))
        current_time = int(time.time()) + time_offset
        time_counter = current_time // time_step

        # Generate HMAC
        time_bytes = struct.pack(">Q", time_counter)
        hmac_digest = hmac.new(secret_bytes, time_bytes, hash_func).digest()

        # Dynamic truncation (RFC 4226)
        offset = hmac_digest[-1] & 0x0F
        binary_code = struct.unpack(">I", hmac_digest[offset : offset + 4])[0]
        binary_code &= 0x7FFFFFFF  # Clear top bit

        # Get the desired number of digits
        otp = binary_code % (10**digits)

        return str(otp).zfill(digits), time_counter

    @classmethod
    def verify_totp(
        cls, secret: str, code: str, window: int = 1, time_step: int = 30, digits: int = 6, algorithm: str = "sha1"
    ) -> Tuple[bool, Optional[int]]:
        """
        Verify a TOTP code.

        Checks the current time step and adjacent steps for clock skew tolerance.

        Args:
            secret: Base32-encoded TOTP secret
            code: Code to verify
            window: Time window tolerance (±window steps)
            time_step: Time step in seconds
            digits: Expected number of digits
            algorithm: Hash algorithm

        Returns:
            Tuple of (is_valid, time_counter if valid else None)
        """
        # Validate code format
        if not code or len(code) != digits or not code.isdigit():
            return False, None

        # Check current time step and adjacent steps (for clock skew)
        for offset in range(-window, window + 1):
            expected_code, counter = cls.generate_totp(
                secret, time_offset=offset * time_step, time_step=time_step, digits=digits, algorithm=algorithm
            )
            # Use constant-time comparison
            if hmac.compare_digest(code, expected_code):
                return True, counter

        return False, None

    # =========================================================================
    # Backup Codes
    # =========================================================================

    @classmethod
    def generate_backup_codes(cls, count: int = 10, length: int = 8) -> List[str]:
        """
        Generate backup codes for 2FA recovery.

        Backup codes are single-use codes that can be used if the user
        loses access to their authenticator.

        Args:
            count: Number of codes to generate
            length: Length of each code (in hex characters)

        Returns:
            List of backup codes (uppercase hex)
        """
        codes = []
        for _ in range(count):
            # Generate random bytes and convert to hex
            code_bytes = secrets.token_bytes(length // 2)
            code = code_bytes.hex().upper()
            codes.append(code)
        return codes

    @staticmethod
    def hash_backup_code(code: str) -> str:
        """
        Hash a backup code for secure storage.

        Uses SHA-256 for hashing. Codes should be hashed, not encrypted,
        since they are single-use and never need to be retrieved.

        Args:
            code: Plain text backup code

        Returns:
            SHA-256 hash of the code
        """
        normalized = code.upper().replace("-", "").replace(" ", "")
        return hashlib.sha256(normalized.encode()).hexdigest()

    def verify_backup_code(self, code: str, hashed_codes: List[str]) -> Optional[int]:
        """
        Verify a backup code against stored hashes.

        Args:
            code: Plain text backup code to verify
            hashed_codes: List of hashed backup codes

        Returns:
            Index of matching code if valid, None otherwise
        """
        code_hash = self.hash_backup_code(code)

        for i, stored_hash in enumerate(hashed_codes):
            if stored_hash and hmac.compare_digest(code_hash, stored_hash):
                return i

        return None

    # =========================================================================
    # Provisioning URI
    # =========================================================================

    def generate_provisioning_uri(self, secret: str, account_name: str, issuer: Optional[str] = None) -> str:
        """
        Generate an otpauth:// URI for authenticator apps.

        This URI can be encoded as a QR code for easy setup.

        Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&...

        Args:
            secret: Base32-encoded TOTP secret
            account_name: User identifier (email, username)
            issuer: App/service name (uses config if not provided)

        Returns:
            otpauth:// URI string
        """
        issuer = issuer or self.config.issuer_name
        label = f"{issuer}:{account_name}"

        params = {
            "secret": secret.replace("=", ""),  # Remove padding
            "issuer": issuer,
            "algorithm": self.config.algorithm.upper(),
            "digits": str(self.config.digits),
            "period": str(self.config.time_step),
        }

        # URL encode the label and parameters
        encoded_label = urllib.parse.quote(label, safe="")
        encoded_params = urllib.parse.urlencode(params)

        return f"otpauth://totp/{encoded_label}?{encoded_params}"

    # =========================================================================
    # Secret Encryption
    # =========================================================================

    def _encrypt_secret(self, secret: str) -> str:
        """
        Encrypt a TOTP secret for storage.

        SECURITY: This method MUST encrypt secrets before storage.
        Plaintext storage is a critical security violation.

        Args:
            secret: Base32-encoded TOTP secret

        Returns:
            Encrypted secret string

        Raises:
            TOTPEncryptionRequiredError: If encryption service is not configured
        """
        if not self.encryption:
            logger.error(
                "SECURITY VIOLATION: Attempted to store TOTP secret without encryption. "
                "Configure an ISecretEncryption implementation."
            )
            raise TOTPEncryptionRequiredError(
                "TOTP encryption service not configured. "
                "Secrets MUST be encrypted before storage. "
                "Configure encryption_service in TOTPService initialization."
            )
        return self.encryption.encrypt(secret)

    def _decrypt_secret(self, encrypted_secret: str) -> str:
        """
        Decrypt a TOTP secret from storage.

        SECURITY: This method requires encryption service to be configured.
        If you have existing plaintext secrets, they must be migrated.

        Args:
            encrypted_secret: Encrypted TOTP secret

        Returns:
            Decrypted Base32-encoded TOTP secret

        Raises:
            TOTPEncryptionRequiredError: If encryption service is not configured
        """
        if not self.encryption:
            logger.error(
                "SECURITY VIOLATION: Attempted to decrypt TOTP secret without encryption service. "
                "Configure an ISecretEncryption implementation."
            )
            raise TOTPEncryptionRequiredError(
                "TOTP encryption service not configured. "
                "Cannot decrypt secrets without encryption service. "
                "Configure encryption_service in TOTPService initialization."
            )
        return self.encryption.decrypt(encrypted_secret)

    # =========================================================================
    # Setup Flow
    # =========================================================================

    @audit_trail(event_type="mfa.totp.setup", severity="INFO")
    def setup_totp(self, user_id: str, account_name: str, issuer: Optional[str] = None) -> SetupResult:
        """
        Set up TOTP 2FA for a user.

        Creates a new TOTP configuration in pending state. User must confirm
        by providing a valid code from their authenticator app.

        Args:
            user_id: User identifier
            account_name: User's email or username (for QR code)
            issuer: Service name (uses config default if not provided)

        Returns:
            SetupResult with secret, provisioning URI, and backup codes

        Raises:
            TOTPAlreadyEnabledError: If TOTP is already enabled for user
        """
        # Check if already enabled
        existing = self.store.get_by_user_id(user_id)
        if existing and existing.status == TOTPStatus.ENABLED.value:
            raise TOTPAlreadyEnabledError()

        try:
            # Generate secret and backup codes
            secret = self.generate_secret(self.config.secret_length)
            backup_codes = self.generate_backup_codes(
                count=self.config.backup_codes_count, length=self.config.backup_code_length
            )

            # Hash backup codes for storage
            hashed_codes = [self.hash_backup_code(code) for code in backup_codes]

            # Encrypt secret for storage
            encrypted_secret = self._encrypt_secret(secret)

            # Create or update TOTP configuration
            self.store.create(
                user_id=user_id,
                encrypted_secret=encrypted_secret,
                algorithm=self.config.algorithm,
                digits=self.config.digits,
                time_step=self.config.time_step,
                status=TOTPStatus.PENDING_CONFIRMATION.value,
            )

            # Store backup codes
            self.store.set_backup_codes(user_id, hashed_codes)

            # Generate provisioning URI
            provisioning_uri = self.generate_provisioning_uri(secret=secret, account_name=account_name, issuer=issuer)

            logger.info("TOTP setup initiated for user %s", user_id)

            return SetupResult(secret=secret, provisioning_uri=provisioning_uri, backup_codes=backup_codes)

        except (TOTPAlreadyEnabledError, TOTPEncryptionRequiredError):
            raise
        except Exception as e:
            logger.error("TOTP setup failed for user %s: %s", user_id, e)
            raise TOTPSetupError(f"Failed to set up TOTP: {e}")

    @audit_trail(event_type="mfa.totp.enabled", severity="INFO")
    def confirm_setup(self, user_id: str, code: str) -> bool:
        """
        Confirm TOTP setup with a valid code.

        The user must provide a valid TOTP code from their authenticator
        to confirm that setup was successful.

        Args:
            user_id: User identifier
            code: TOTP code from authenticator app

        Returns:
            True if confirmed successfully

        Raises:
            TOTPNotEnabledError: If no pending TOTP setup exists
            TOTPInvalidCodeError: If code is invalid
        """
        totp_data = self.store.get_by_user_id(user_id)
        if totp_data is None or totp_data.status != TOTPStatus.PENDING_CONFIRMATION.value:
            raise TOTPNotEnabledError("No pending TOTP setup found")

        # Decrypt secret and verify code
        secret = self._decrypt_secret(totp_data.encrypted_secret)
        is_valid, counter = self.verify_totp(
            secret=secret,
            code=code,
            window=self.config.window,
            time_step=totp_data.time_step,
            digits=totp_data.digits,
            algorithm=totp_data.algorithm,
        )

        if not is_valid:
            self.store.log_verification(
                user_id=user_id, success=False, verification_type="totp", failure_reason="invalid_code_during_setup"
            )
            raise TOTPInvalidCodeError()

        # Enable TOTP
        self.store.update_status(user_id, TOTPStatus.ENABLED.value)
        self.store.record_successful_verification(user_id, counter)
        self.store.log_verification(user_id=user_id, success=True, verification_type="totp")

        logger.info("TOTP enabled for user %s", user_id)
        return True

    @audit_trail(event_type="mfa.totp.disabled", severity="WARNING")
    def disable(self, user_id: str) -> bool:
        """
        Disable TOTP 2FA for a user.

        Args:
            user_id: User identifier

        Returns:
            True if disabled successfully
        """
        result = self.store.delete(user_id)
        if result:
            logger.info("TOTP disabled for user %s", user_id)
        return result

    # =========================================================================
    # Verification
    # =========================================================================

    @audit_trail(event_type="mfa.totp.verify", severity="INFO")
    def verify(self, user_id: str, code: str, ip_address: Optional[str] = None, user_agent: str = "") -> VerifyResult:
        """
        Verify a TOTP code or backup code.

        Handles both regular TOTP codes and backup codes for recovery.

        Args:
            user_id: User identifier
            code: TOTP code or backup code
            ip_address: Client IP for logging
            user_agent: Client user agent for logging

        Returns:
            VerifyResult with success status and details

        Raises:
            TOTPNotEnabledError: If TOTP is not enabled
            TOTPAccountLockedError: If account is locked
            TOTPCodeReusedError: If code was already used (replay)
            TOTPVerificationError: If verification fails
        """
        totp_data = self.store.get_by_user_id(user_id)
        if totp_data is None or totp_data.status != TOTPStatus.ENABLED.value:
            raise TOTPNotEnabledError()

        # Check if account is locked
        if totp_data.is_locked():
            raise TOTPAccountLockedError(lockout_remaining=self._get_lockout_remaining(totp_data))

        # Normalize code
        normalized_code = code.strip().replace("-", "").replace(" ", "")

        # Try TOTP verification first
        if len(normalized_code) == totp_data.digits and normalized_code.isdigit():
            return self._verify_totp_code(
                user_id=user_id, totp_data=totp_data, code=normalized_code, ip_address=ip_address, user_agent=user_agent
            )

        # Try backup code verification
        return self._verify_backup_code(
            user_id=user_id, totp_data=totp_data, code=normalized_code, ip_address=ip_address, user_agent=user_agent
        )

    def _verify_totp_code(
        self, user_id: str, totp_data: TOTP2FAData, code: str, ip_address: Optional[str] = None, user_agent: str = ""
    ) -> VerifyResult:
        """Verify a TOTP code."""
        # Decrypt secret
        secret = self._decrypt_secret(totp_data.encrypted_secret)

        # Verify code
        is_valid, counter = self.verify_totp(
            secret=secret,
            code=code,
            window=self.config.window,
            time_step=totp_data.time_step,
            digits=totp_data.digits,
            algorithm=totp_data.algorithm,
        )

        if not is_valid:
            self._handle_failed_verification(
                user_id=user_id,
                verification_type="totp",
                reason="invalid_code",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise TOTPVerificationError()

        # Check for replay attack
        if counter and self.store.is_counter_used(user_id, counter):
            self._handle_failed_verification(
                user_id=user_id,
                verification_type="totp",
                reason="code_reused",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise TOTPCodeReusedError()

        # Record success
        self.store.record_successful_verification(user_id, counter)
        self.store.log_verification(
            user_id=user_id, success=True, verification_type="totp", ip_address=ip_address, user_agent=user_agent
        )

        return VerifyResult(
            success=True, verification_type="totp", backup_codes_remaining=totp_data.backup_codes_remaining
        )

    def _verify_backup_code(
        self, user_id: str, totp_data: TOTP2FAData, code: str, ip_address: Optional[str] = None, user_agent: str = ""
    ) -> VerifyResult:
        """Verify a backup code."""
        code_index = self.verify_backup_code(code, totp_data.backup_codes_hash)

        if code_index is None:
            self._handle_failed_verification(
                user_id=user_id,
                verification_type="backup",
                reason="invalid_backup_code",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise TOTPInvalidBackupCodeError()

        # Check if already used
        if not totp_data.backup_codes_hash[code_index]:
            raise TOTPBackupCodeUsedError()

        # Mark as used
        self.store.use_backup_code(user_id, code_index)

        # Record success (no counter for backup codes)
        self.store.log_verification(
            user_id=user_id, success=True, verification_type="backup", ip_address=ip_address, user_agent=user_agent
        )

        remaining = totp_data.backup_codes_remaining - 1

        logger.info("Backup code used for user %s (remaining: %d)", user_id, remaining)

        return VerifyResult(success=True, verification_type="backup", backup_codes_remaining=remaining)

    def _handle_failed_verification(
        self, user_id: str, verification_type: str, reason: str, ip_address: Optional[str] = None, user_agent: str = ""
    ) -> None:
        """Handle a failed verification attempt."""
        is_locked = self.store.record_failed_attempt(
            user_id=user_id, max_attempts=self.config.max_attempts, lockout_duration=self.config.lockout_duration
        )

        self.store.log_verification(
            user_id=user_id,
            success=False,
            verification_type=verification_type,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=reason,
        )

        if is_locked:
            logger.warning("TOTP account locked for user %s due to failed attempts", user_id)

    def _get_lockout_remaining(self, totp_data: TOTP2FAData) -> int:
        """Calculate remaining lockout time in seconds."""
        if totp_data.locked_until is None:
            return 0
        from django.utils import timezone

        delta = totp_data.locked_until - timezone.now()
        return max(0, int(delta.total_seconds()))

    # =========================================================================
    # Status and Info
    # =========================================================================

    def is_enabled(self, user_id: str) -> bool:
        """Check if TOTP is enabled for a user."""
        totp_data = self.store.get_by_user_id(user_id)
        return totp_data is not None and totp_data.status == TOTPStatus.ENABLED.value

    def get_status(self, user_id: str) -> Optional[str]:
        """Get TOTP status for a user."""
        totp_data = self.store.get_by_user_id(user_id)
        return totp_data.status if totp_data else None

    def get_backup_codes_remaining(self, user_id: str) -> int:
        """Get number of unused backup codes for a user."""
        totp_data = self.store.get_by_user_id(user_id)
        return totp_data.backup_codes_remaining if totp_data else 0

    @audit_trail(event_type="mfa.backup_codes.regenerated", severity="WARNING")
    def regenerate_backup_codes(self, user_id: str) -> List[str]:
        """
        Regenerate backup codes for a user.

        Invalidates all existing backup codes and generates new ones.

        Args:
            user_id: User identifier

        Returns:
            List of new backup codes (plain text, show once)

        Raises:
            TOTPNotEnabledError: If TOTP is not enabled
        """
        totp_data = self.store.get_by_user_id(user_id)
        if totp_data is None or totp_data.status != TOTPStatus.ENABLED.value:
            raise TOTPNotEnabledError()

        # Generate new codes
        backup_codes = self.generate_backup_codes(
            count=self.config.backup_codes_count, length=self.config.backup_code_length
        )
        hashed_codes = [self.hash_backup_code(code) for code in backup_codes]

        # Store new hashed codes
        self.store.set_backup_codes(user_id, hashed_codes)

        logger.info("Backup codes regenerated for user %s", user_id)

        return backup_codes


# Optional encryption interface
class ISecretEncryption:
    """Interface for TOTP secret encryption."""

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret."""
        raise NotImplementedError

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a secret."""
        raise NotImplementedError
