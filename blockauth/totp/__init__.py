"""
BlockAuth TOTP 2FA Module

Time-based One-Time Password (TOTP) two-factor authentication
implementing RFC 6238 with backup codes and rate limiting.

Features:
- RFC 6238 TOTP algorithm (SHA1, SHA256, SHA512)
- QR code provisioning URIs
- Backup codes for recovery
- Rate limiting and lockout
- Replay attack prevention
- Audit logging
- Encrypted secret storage (required)

Usage:
    from blockauth.totp import is_enabled, get_totp_service

    # Check if TOTP module is enabled
    if is_enabled():
        service = get_totp_service()

        # Setup TOTP for a user
        result = service.setup_totp(user_id, email)
        # Display result.provisioning_uri as QR code
        # Display result.backup_codes once

        # Confirm setup with code from authenticator
        service.confirm_setup(user_id, code)

        # Verify during login
        if service.verify(user_id, code):
            # Grant access

Configuration (in Django settings BLOCK_AUTH_SETTINGS):
    BLOCK_AUTH_SETTINGS = {
        # Enable TOTP via FEATURES dict
        "FEATURES": {
            "TOTP_2FA": True,
        },
        # TOTP configuration in dedicated object
        "TOTP_CONFIG": {
            "ENCRYPTION_KEY": "your-fernet-key",  # REQUIRED
            "ISSUER_NAME": "YourAppName",
            "DIGITS": 6,
            "TIME_STEP": 30,
            "ALGORITHM": "sha1",
            "WINDOW": 1,
            "SECRET_LENGTH": 32,
            "BACKUP_CODES_COUNT": 10,
            "MAX_ATTEMPTS": 5,
            "LOCKOUT_DURATION": 300,
        },
    }

Generate encryption key:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())

Startup Validation (recommended in Django AppConfig):
    from blockauth.totp.services import validate_totp_encryption_config
    validate_totp_encryption_config()  # Raises if misconfigured
"""

from .constants import DEFAULTS, TOTP_CONFIG_KEY, TOTP_FEATURE_FLAG, TOTPAlgorithm, TOTPConfigKeys, TOTPStatus


def is_enabled() -> bool:
    """
    Check if TOTP 2FA is enabled in configuration.

    Checks FEATURES["TOTP_2FA"] in BLOCK_AUTH_SETTINGS.

    Returns:
        True if TOTP module is enabled, False otherwise
    """
    try:
        from blockauth.constants import ConfigKeys
        from blockauth.utils.config import get_config

        features = get_config(ConfigKeys.FEATURES)
        return features.get(TOTP_FEATURE_FLAG, False)
    except (ImportError, AttributeError):
        # Not in Django context or config not available
        return False


def get_totp_config():
    """
    Get TOTP configuration from TOTP_CONFIG object.

    Returns:
        TOTPConfiguration: Configuration object with all settings
    """
    from .config import get_totp_config as _get_config

    return _get_config()


def get_totp_service(encryption_service=None) -> "TOTPService":
    """
    Get a configured TOTP service instance.

    The encryption service is automatically loaded from TOTP_CONFIG
    if not provided explicitly.

    Args:
        encryption_service: Optional encryption service for secrets.
                           If None, uses the configured encryption from settings.

    Returns:
        Configured TOTPService instance

    Raises:
        TOTPEncryptionNotConfiguredError: If ENCRYPTION_KEY is not configured
        ImportError: If required dependencies are not available
    """
    from .services import TOTPService, get_encryption_service
    from .storage import DjangoTOTP2FAStore

    store = DjangoTOTP2FAStore()
    config = get_totp_config()

    # Use provided encryption service or load from settings
    if encryption_service is None:
        encryption_service = get_encryption_service()

    return TOTPService(store=store, config=config, encryption_service=encryption_service)


__all__ = [
    # Module functions
    "is_enabled",
    "get_totp_service",
    "get_totp_config",
    # Configuration
    "TOTPConfigKeys",
    "TOTP_CONFIG_KEY",
    "TOTP_FEATURE_FLAG",
    "DEFAULTS",
    # Constants
    "TOTPStatus",
    "TOTPAlgorithm",
]
