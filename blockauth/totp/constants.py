"""
TOTP 2FA Constants and Configuration Keys.

This module defines all constants, configuration keys, error codes,
and default values for the TOTP 2FA functionality.
"""
from enum import Enum


class TOTPConfigKeys:
    """Configuration keys for TOTP 2FA settings."""

    # Core TOTP settings
    ENABLED = "TOTP_ENABLED"
    ISSUER_NAME = "TOTP_ISSUER_NAME"
    DIGITS = "TOTP_DIGITS"
    TIME_STEP = "TOTP_TIME_STEP"
    ALGORITHM = "TOTP_ALGORITHM"
    WINDOW = "TOTP_WINDOW"

    # Secret settings
    SECRET_LENGTH = "TOTP_SECRET_LENGTH"

    # Backup codes settings
    BACKUP_CODES_COUNT = "TOTP_BACKUP_CODES_COUNT"
    BACKUP_CODE_LENGTH = "TOTP_BACKUP_CODE_LENGTH"

    # Rate limiting
    MAX_ATTEMPTS = "TOTP_MAX_ATTEMPTS"
    LOCKOUT_DURATION = "TOTP_LOCKOUT_DURATION"

    # Security
    REQUIRE_CONFIRMATION = "TOTP_REQUIRE_CONFIRMATION"


class TOTPErrorCodes:
    """Error codes for TOTP operations."""

    # Setup errors
    ALREADY_ENABLED = "totp_already_enabled"
    NOT_ENABLED = "totp_not_enabled"
    SETUP_FAILED = "totp_setup_failed"
    INVALID_SECRET = "totp_invalid_secret"

    # Verification errors
    INVALID_CODE = "totp_invalid_code"
    CODE_EXPIRED = "totp_code_expired"
    CODE_REUSED = "totp_code_reused"
    VERIFICATION_FAILED = "totp_verification_failed"

    # Backup code errors
    INVALID_BACKUP_CODE = "totp_invalid_backup_code"
    BACKUP_CODE_USED = "totp_backup_code_used"
    NO_BACKUP_CODES = "totp_no_backup_codes"

    # Rate limiting errors
    TOO_MANY_ATTEMPTS = "totp_too_many_attempts"
    ACCOUNT_LOCKED = "totp_account_locked"

    # General errors
    STORAGE_ERROR = "totp_storage_error"
    CONFIGURATION_ERROR = "totp_configuration_error"

    # Security errors
    ENCRYPTION_REQUIRED = "totp_encryption_required"


class TOTPStatus(str, Enum):
    """Status of TOTP 2FA for a user."""

    DISABLED = "disabled"
    PENDING_CONFIRMATION = "pending_confirmation"
    ENABLED = "enabled"


class TOTPAlgorithm(str, Enum):
    """Supported TOTP hash algorithms (RFC 6238)."""

    SHA1 = "sha1"      # Default, most compatible
    SHA256 = "sha256"  # More secure, less compatible
    SHA512 = "sha512"  # Most secure, least compatible


# Default configuration values
DEFAULTS = {
    TOTPConfigKeys.ENABLED: False,
    TOTPConfigKeys.ISSUER_NAME: "BlockAuth",
    TOTPConfigKeys.DIGITS: 6,
    TOTPConfigKeys.TIME_STEP: 30,  # 30 seconds (RFC 6238 standard)
    TOTPConfigKeys.ALGORITHM: TOTPAlgorithm.SHA1.value,
    TOTPConfigKeys.WINDOW: 1,  # ±1 time step tolerance for clock skew
    TOTPConfigKeys.SECRET_LENGTH: 20,  # 160 bits (RFC 4226 minimum)
    TOTPConfigKeys.BACKUP_CODES_COUNT: 10,
    TOTPConfigKeys.BACKUP_CODE_LENGTH: 8,
    TOTPConfigKeys.MAX_ATTEMPTS: 5,
    TOTPConfigKeys.LOCKOUT_DURATION: 300,  # 5 minutes in seconds
    TOTPConfigKeys.REQUIRE_CONFIRMATION: True,
}


# Error messages
ERROR_MESSAGES = {
    TOTPErrorCodes.ALREADY_ENABLED: "TOTP 2FA is already enabled for this account.",
    TOTPErrorCodes.NOT_ENABLED: "TOTP 2FA is not enabled for this account.",
    TOTPErrorCodes.SETUP_FAILED: "Failed to set up TOTP 2FA.",
    TOTPErrorCodes.INVALID_SECRET: "Invalid TOTP secret format.",
    TOTPErrorCodes.INVALID_CODE: "Invalid TOTP code.",
    TOTPErrorCodes.CODE_EXPIRED: "TOTP code has expired.",
    TOTPErrorCodes.CODE_REUSED: "This TOTP code has already been used.",
    TOTPErrorCodes.VERIFICATION_FAILED: "TOTP verification failed.",
    TOTPErrorCodes.INVALID_BACKUP_CODE: "Invalid backup code.",
    TOTPErrorCodes.BACKUP_CODE_USED: "This backup code has already been used.",
    TOTPErrorCodes.NO_BACKUP_CODES: "No backup codes available.",
    TOTPErrorCodes.TOO_MANY_ATTEMPTS: "Too many failed attempts. Please try again later.",
    TOTPErrorCodes.ACCOUNT_LOCKED: "Account is temporarily locked due to failed attempts.",
    TOTPErrorCodes.STORAGE_ERROR: "Failed to store TOTP data.",
    TOTPErrorCodes.CONFIGURATION_ERROR: "TOTP configuration error.",
    TOTPErrorCodes.ENCRYPTION_REQUIRED: "TOTP encryption service not configured. Secrets must be encrypted.",
}
