"""
TOTP 2FA Custom Exceptions.

Provides specific exception types for TOTP operations
with error codes for API responses.
"""

from typing import Optional

from .constants import ERROR_MESSAGES, TOTPErrorCodes


class TOTPError(Exception):
    """Base exception for all TOTP errors."""

    error_code: str = "totp_error"
    default_message: str = "A TOTP error occurred."

    def __init__(self, message: Optional[str] = None, error_code: Optional[str] = None):
        self.message = message or self.default_message
        if error_code:
            self.error_code = error_code
        super().__init__(self.message)

    def to_dict(self) -> dict:
        """Convert exception to API response dict."""
        return {
            "error": self.error_code,
            "message": self.message,
        }


class TOTPAlreadyEnabledError(TOTPError):
    """Raised when TOTP is already enabled for a user."""

    error_code = TOTPErrorCodes.ALREADY_ENABLED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.ALREADY_ENABLED]


class TOTPNotEnabledError(TOTPError):
    """Raised when TOTP is not enabled but operation requires it."""

    error_code = TOTPErrorCodes.NOT_ENABLED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.NOT_ENABLED]


class TOTPSetupError(TOTPError):
    """Raised when TOTP setup fails."""

    error_code = TOTPErrorCodes.SETUP_FAILED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.SETUP_FAILED]


class TOTPInvalidSecretError(TOTPError):
    """Raised when TOTP secret is invalid."""

    error_code = TOTPErrorCodes.INVALID_SECRET
    default_message = ERROR_MESSAGES[TOTPErrorCodes.INVALID_SECRET]


class TOTPInvalidCodeError(TOTPError):
    """Raised when TOTP code is invalid."""

    error_code = TOTPErrorCodes.INVALID_CODE
    default_message = ERROR_MESSAGES[TOTPErrorCodes.INVALID_CODE]


class TOTPCodeExpiredError(TOTPError):
    """Raised when TOTP code has expired."""

    error_code = TOTPErrorCodes.CODE_EXPIRED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.CODE_EXPIRED]


class TOTPCodeReusedError(TOTPError):
    """Raised when TOTP code is reused (replay attack prevention)."""

    error_code = TOTPErrorCodes.CODE_REUSED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.CODE_REUSED]


class TOTPVerificationError(TOTPError):
    """Raised when TOTP verification fails."""

    error_code = TOTPErrorCodes.VERIFICATION_FAILED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.VERIFICATION_FAILED]


class TOTPInvalidBackupCodeError(TOTPError):
    """Raised when backup code is invalid."""

    error_code = TOTPErrorCodes.INVALID_BACKUP_CODE
    default_message = ERROR_MESSAGES[TOTPErrorCodes.INVALID_BACKUP_CODE]


class TOTPBackupCodeUsedError(TOTPError):
    """Raised when backup code has already been used."""

    error_code = TOTPErrorCodes.BACKUP_CODE_USED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.BACKUP_CODE_USED]


class TOTPNoBackupCodesError(TOTPError):
    """Raised when no backup codes are available."""

    error_code = TOTPErrorCodes.NO_BACKUP_CODES
    default_message = ERROR_MESSAGES[TOTPErrorCodes.NO_BACKUP_CODES]


class TOTPTooManyAttemptsError(TOTPError):
    """Raised when too many verification attempts are made."""

    error_code = TOTPErrorCodes.TOO_MANY_ATTEMPTS
    default_message = ERROR_MESSAGES[TOTPErrorCodes.TOO_MANY_ATTEMPTS]

    def __init__(
        self,
        message: Optional[str] = None,
        lockout_until: Optional[int] = None,
    ):
        super().__init__(message)
        self.lockout_until = lockout_until

    def to_dict(self) -> dict:
        result = super().to_dict()
        if self.lockout_until:
            result["lockout_until"] = self.lockout_until
        return result


class TOTPAccountLockedError(TOTPError):
    """Raised when account is locked due to failed attempts."""

    error_code = TOTPErrorCodes.ACCOUNT_LOCKED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.ACCOUNT_LOCKED]

    def __init__(
        self,
        message: Optional[str] = None,
        lockout_remaining: Optional[int] = None,
    ):
        super().__init__(message)
        self.lockout_remaining = lockout_remaining

    def to_dict(self) -> dict:
        result = super().to_dict()
        if self.lockout_remaining:
            result["lockout_remaining_seconds"] = self.lockout_remaining
        return result


class TOTPStorageError(TOTPError):
    """Raised when TOTP storage operations fail."""

    error_code = TOTPErrorCodes.STORAGE_ERROR
    default_message = ERROR_MESSAGES[TOTPErrorCodes.STORAGE_ERROR]


class TOTPConfigurationError(TOTPError):
    """Raised when TOTP configuration is invalid."""

    error_code = TOTPErrorCodes.CONFIGURATION_ERROR
    default_message = ERROR_MESSAGES[TOTPErrorCodes.CONFIGURATION_ERROR]


class TOTPEncryptionRequiredError(TOTPError):
    """
    Raised when encryption service is not configured.

    SECURITY: TOTP secrets MUST be encrypted before storage.
    Storing plaintext secrets is a critical security violation.
    Configure an ISecretEncryption implementation before using TOTP.
    """

    error_code = TOTPErrorCodes.ENCRYPTION_REQUIRED
    default_message = ERROR_MESSAGES[TOTPErrorCodes.ENCRYPTION_REQUIRED]
