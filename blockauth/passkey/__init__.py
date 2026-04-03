"""
Passkey/WebAuthn Module for BlockAuth

This module provides WebAuthn/FIDO2 passwordless authentication capabilities.
It enables users to authenticate using biometrics (Face ID, Touch ID, Windows Hello)
or hardware security keys (YubiKey, Titan Key).

IMPORTANT: This is an OPTIONAL module that must be explicitly enabled.
It will not be loaded unless FEATURES['PASSKEY_AUTH']=True is set in BLOCK_AUTH_SETTINGS.

Key Features:
- Passwordless authentication using WebAuthn/FIDO2
- Support for platform authenticators (Face ID, Touch ID, Windows Hello)
- Support for roaming authenticators (YubiKey, phone as authenticator)
- Discoverable credentials (passwordless without username)
- Multi-device support with credential management
- Signature counter validation for clone detection
- Framework-agnostic design

Configuration (in Django settings BLOCK_AUTH_SETTINGS):
    BLOCK_AUTH_SETTINGS = {
        # Enable passkey via FEATURES dict
        "FEATURES": {
            "PASSKEY_AUTH": True,
        },
        # Passkey configuration in dedicated object
        "PASSKEY_CONFIG": {
            "RP_ID": "example.com",
            "RP_NAME": "My Application",
            "ALLOWED_ORIGINS": ["https://example.com"],
            "USER_VERIFICATION": "required",
            "ATTESTATION": "none",
            # Optional feature flags
            "FEATURES": {
                "DISCOVERABLE_CREDENTIALS": True,
                "COUNTER_VALIDATION": True,
            },
        },
    }

Usage:
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
    PASSKEY_CONFIG_KEY,
    PASSKEY_FEATURE_FLAG,
    AttestationConveyance,
    AuthenticatorAttachment,
    AuthenticatorTransport,
    COSEAlgorithm,
    PasskeyConfigKeys,
    PasskeyErrorCodes,
    PasskeyFeatureFlags,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from .exceptions import (
    AttestationVerificationError,
    ChallengeAlreadyUsedError,
    ChallengeExpiredError,
    ConfigurationError,
    CounterRegressionError,
    CredentialNotFoundError,
    CredentialRevokedError,
    InvalidCredentialDataError,
    InvalidOriginError,
    InvalidRpIdError,
    MaxCredentialsReachedError,
    PasskeyError,
    PasskeyNotEnabledError,
    RateLimitExceededError,
    SignatureVerificationError,
)

__all__ = [
    # Public API
    "is_enabled",
    "get_passkey_service",
    "get_passkey_config",
    "get_credential_store",
    # Configuration keys
    "PASSKEY_CONFIG_KEY",
    "PASSKEY_FEATURE_FLAG",
    "PasskeyConfigKeys",
    # Constants
    "AttestationConveyance",
    "AuthenticatorAttachment",
    "ResidentKeyRequirement",
    "UserVerificationRequirement",
    "COSEAlgorithm",
    "AuthenticatorTransport",
    "PasskeyFeatureFlags",
    "PasskeyErrorCodes",
    # Exceptions
    "PasskeyError",
    "PasskeyNotEnabledError",
    "ChallengeExpiredError",
    "ChallengeAlreadyUsedError",
    "InvalidOriginError",
    "InvalidRpIdError",
    "CredentialNotFoundError",
    "CredentialRevokedError",
    "CounterRegressionError",
    "SignatureVerificationError",
    "MaxCredentialsReachedError",
    "AttestationVerificationError",
    "RateLimitExceededError",
    "InvalidCredentialDataError",
    "ConfigurationError",
]


def is_enabled() -> bool:
    """
    Check if Passkey module is enabled in the current project.

    Checks FEATURES["PASSKEY_AUTH"] in BLOCK_AUTH_SETTINGS.

    Returns:
        bool: True if PASSKEY_AUTH is enabled in settings
    """
    try:
        from blockauth.constants import ConfigKeys
        from blockauth.utils.config import get_config

        features = get_config(ConfigKeys.FEATURES)
        return features.get(PASSKEY_FEATURE_FLAG, False)
    except (ImportError, AttributeError):
        # Not in Django context or config not available
        return False


def get_passkey_config():
    """
    Get passkey configuration from PASSKEY_CONFIG object.

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

    if config.storage_backend == "memory":
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
