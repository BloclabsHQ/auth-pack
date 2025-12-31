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
        'TOTP_ENABLED': True,
        'TOTP_ENCRYPTION_KEY': 'your-fernet-key-here',  # REQUIRED - generate with Fernet.generate_key()
        'TOTP_ISSUER_NAME': 'YourAppName',
        'TOTP_DIGITS': 6,
        'TOTP_TIME_STEP': 30,
        'TOTP_ALGORITHM': 'sha1',
        'TOTP_WINDOW': 1,
        'TOTP_SECRET_LENGTH': 32,  # 256 bits recommended
        'TOTP_BACKUP_CODES_COUNT': 10,
        'TOTP_MAX_ATTEMPTS': 5,
        'TOTP_LOCKOUT_DURATION': 300,
    }

Generate encryption key:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())

Startup Validation (recommended in Django AppConfig):
    from blockauth.totp.services import validate_totp_encryption_config
    validate_totp_encryption_config()  # Raises if misconfigured
"""
from typing import Optional

from ..settings import blockauth_settings
from .config import get_totp_config, TOTPConfiguration
from .constants import (
    DEFAULTS,
    TOTPConfigKeys,
    TOTPStatus,
    TOTPAlgorithm,
)


def is_enabled() -> bool:
    """
    Check if TOTP 2FA is enabled in configuration.

    Returns:
        True if TOTP module is enabled, False otherwise
    """
    return blockauth_settings.get(
        TOTPConfigKeys.ENABLED,
        DEFAULTS[TOTPConfigKeys.ENABLED]
    )


def get_totp_service(encryption_service=None) -> 'TOTPService':
    """
    Get a configured TOTP service instance.

    The encryption service is automatically loaded from Django settings
    (TOTP_ENCRYPTION_KEY) if not provided explicitly.

    Args:
        encryption_service: Optional encryption service for secrets.
                           If None, uses the configured encryption from settings.

    Returns:
        Configured TOTPService instance

    Raises:
        TOTPEncryptionNotConfiguredError: If TOTP_ENCRYPTION_KEY is not configured
        ImportError: If required dependencies are not available
    """
    from .services import TOTPService, get_encryption_service
    from .storage import DjangoTOTP2FAStore

    store = DjangoTOTP2FAStore()
    config = get_totp_config()

    # Use provided encryption service or load from settings
    if encryption_service is None:
        encryption_service = get_encryption_service()

    return TOTPService(
        store=store,
        config=config,
        encryption_service=encryption_service
    )


__all__ = [
    # Module functions
    'is_enabled',
    'get_totp_service',
    'get_totp_config',

    # Configuration
    'TOTPConfiguration',
    'TOTPConfigKeys',
    'DEFAULTS',

    # Constants
    'TOTPStatus',
    'TOTPAlgorithm',
]
