"""
Passkey/WebAuthn Module for BlockAuth

This module provides WebAuthn/FIDO2 passwordless authentication capabilities.
It enables users to authenticate using biometrics (Face ID, Touch ID, Windows Hello)
or hardware security keys (YubiKey, Titan Key).

IMPORTANT: This is an OPTIONAL module that must be explicitly enabled.
It will not be loaded unless PASSKEY_ENABLED=True is set in BLOCK_AUTH_SETTINGS.

Key Features:
- Passwordless authentication using WebAuthn/FIDO2
- Support for platform authenticators (Face ID, Touch ID, Windows Hello)
- Support for roaming authenticators (YubiKey, phone as authenticator)
- Discoverable credentials (passwordless without username)
- Multi-device support with credential management
- Signature counter validation for clone detection
- Framework-agnostic design

Usage:
    # In your project's settings.py
    BLOCK_AUTH_SETTINGS = {
        'PASSKEY_ENABLED': True,
        'PASSKEY_RP_ID': 'example.com',
        'PASSKEY_RP_NAME': 'My Application',
        'PASSKEY_ALLOWED_ORIGINS': ['https://example.com'],
    }

    # In your code
    from blockauth.passkey import is_enabled, get_passkey_service

    if is_enabled():
        passkey_service = get_passkey_service()

        # Generate registration options
        options = passkey_service.generate_registration_options(
            user_id='user-123',
            username='user@example.com',
            display_name='John Doe'
        )

        # Verify registration response
        credential = passkey_service.verify_registration(
            credential_data=registration_response,
            user_id='user-123'
        )

        # Generate authentication options
        options = passkey_service.generate_authentication_options(
            user_id='user-123'  # Optional for discoverable credentials
        )

        # Verify authentication response
        result = passkey_service.verify_authentication(
            credential_data=authentication_response
        )
"""

from .constants import (
    PasskeyConfigKeys,
    AttestationConveyance,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    COSEAlgorithm,
    AuthenticatorTransport,
    PasskeyFeatureFlags,
    PasskeyErrorCodes,
)

from .exceptions import (
    PasskeyError,
    PasskeyNotEnabledError,
    ChallengeExpiredError,
    ChallengeAlreadyUsedError,
    InvalidOriginError,
    InvalidRpIdError,
    CredentialNotFoundError,
    CredentialRevokedError,
    CounterRegressionError,
    SignatureVerificationError,
    MaxCredentialsReachedError,
    AttestationVerificationError,
    RateLimitExceededError,
    InvalidCredentialDataError,
    ConfigurationError,
)

__all__ = [
    # Public API
    'is_enabled',
    'get_passkey_service',
    'get_passkey_config',
    'get_credential_store',

    # Constants
    'PasskeyConfigKeys',
    'AttestationConveyance',
    'AuthenticatorAttachment',
    'ResidentKeyRequirement',
    'UserVerificationRequirement',
    'COSEAlgorithm',
    'AuthenticatorTransport',
    'PasskeyFeatureFlags',
    'PasskeyErrorCodes',

    # Exceptions
    'PasskeyError',
    'PasskeyNotEnabledError',
    'ChallengeExpiredError',
    'ChallengeAlreadyUsedError',
    'InvalidOriginError',
    'InvalidRpIdError',
    'CredentialNotFoundError',
    'CredentialRevokedError',
    'CounterRegressionError',
    'SignatureVerificationError',
    'MaxCredentialsReachedError',
    'AttestationVerificationError',
    'RateLimitExceededError',
    'InvalidCredentialDataError',
    'ConfigurationError',
]


def is_enabled() -> bool:
    """
    Check if Passkey module is enabled in the current project.

    Returns:
        bool: True if PASSKEY_ENABLED=True in BLOCK_AUTH_SETTINGS
    """
    try:
        from django.conf import settings
        block_auth_settings = getattr(settings, 'BLOCK_AUTH_SETTINGS', {})
        return block_auth_settings.get('PASSKEY_ENABLED', False)
    except ImportError:
        # Not in Django context
        return False


def get_passkey_config():
    """
    Get passkey configuration.

    Returns:
        PasskeyConfiguration: Configuration object with all settings

    Raises:
        PasskeyNotEnabledError: If passkey is not enabled
        ConfigurationError: If configuration is invalid
    """
    if not is_enabled():
        raise PasskeyNotEnabledError()

    from .config import get_passkey_config as _get_config
    return _get_config()


def get_passkey_service():
    """
    Get the main Passkey service.

    Returns:
        PasskeyService: Service for registration and authentication

    Raises:
        PasskeyNotEnabledError: If passkey is not enabled
    """
    if not is_enabled():
        raise PasskeyNotEnabledError()

    from .services.passkey_service import PasskeyService
    return PasskeyService()


def get_credential_store():
    """
    Get the credential storage backend.

    Returns:
        ICredentialStore: Storage implementation based on configuration

    Raises:
        PasskeyNotEnabledError: If passkey is not enabled
    """
    if not is_enabled():
        raise PasskeyNotEnabledError()

    from .config import get_passkey_config
    config = get_passkey_config()

    if config.storage_backend == 'memory':
        from .storage.memory_storage import MemoryCredentialStore
        return MemoryCredentialStore()
    else:
        from .storage.django_storage import DjangoCredentialStore
        return DjangoCredentialStore()


def get_challenge_service():
    """
    Get the challenge service.

    Returns:
        ChallengeService: Service for challenge generation and validation

    Raises:
        PasskeyNotEnabledError: If passkey is not enabled
    """
    if not is_enabled():
        raise PasskeyNotEnabledError()

    from .services.challenge_service import ChallengeService
    return ChallengeService()
