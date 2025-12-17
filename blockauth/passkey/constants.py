"""
Passkey/WebAuthn Constants for BlockAuth

This module defines all constants, enums, and configuration keys
for the Passkey authentication module.
"""

from enum import Enum, IntEnum


class PasskeyConfigKeys:
    """Configuration key names for BLOCK_AUTH_SETTINGS"""

    # Master switch
    ENABLED = 'PASSKEY_ENABLED'

    # Relying Party configuration
    RP_ID = 'PASSKEY_RP_ID'
    RP_NAME = 'PASSKEY_RP_NAME'
    ALLOWED_ORIGINS = 'PASSKEY_ALLOWED_ORIGINS'

    # Attestation
    ATTESTATION = 'PASSKEY_ATTESTATION'

    # Authenticator preferences
    AUTHENTICATOR_ATTACHMENT = 'PASSKEY_AUTHENTICATOR_ATTACHMENT'
    RESIDENT_KEY = 'PASSKEY_RESIDENT_KEY'
    USER_VERIFICATION = 'PASSKEY_USER_VERIFICATION'

    # Timeouts
    REGISTRATION_TIMEOUT = 'PASSKEY_REGISTRATION_TIMEOUT'
    AUTHENTICATION_TIMEOUT = 'PASSKEY_AUTHENTICATION_TIMEOUT'

    # Challenge configuration
    CHALLENGE_LENGTH = 'PASSKEY_CHALLENGE_LENGTH'
    CHALLENGE_EXPIRY = 'PASSKEY_CHALLENGE_EXPIRY'

    # Algorithms
    SUPPORTED_ALGORITHMS = 'PASSKEY_SUPPORTED_ALGORITHMS'

    # Limits
    MAX_CREDENTIALS_PER_USER = 'PASSKEY_MAX_CREDENTIALS_PER_USER'

    # Storage
    STORAGE_BACKEND = 'PASSKEY_STORAGE_BACKEND'

    # Rate limiting
    RATE_LIMITS = 'PASSKEY_RATE_LIMITS'

    # Hooks/Triggers
    POST_REGISTRATION_TRIGGER = 'PASSKEY_POST_REGISTRATION_TRIGGER'
    POST_AUTHENTICATION_TRIGGER = 'PASSKEY_POST_AUTHENTICATION_TRIGGER'

    # Feature flags
    FEATURES = 'PASSKEY_FEATURES'


class AttestationConveyance(str, Enum):
    """
    Attestation conveyance preference.

    Controls whether the authenticator provides attestation data
    to prove the authenticator's legitimacy.
    """
    NONE = 'none'           # No attestation (default, recommended for most apps)
    INDIRECT = 'indirect'   # Anonymized attestation
    DIRECT = 'direct'       # Full attestation from authenticator
    ENTERPRISE = 'enterprise'  # Enterprise attestation (requires pre-registration)


class AuthenticatorAttachment(str, Enum):
    """
    Authenticator attachment modality.

    Controls which type of authenticator is allowed.
    """
    PLATFORM = 'platform'           # Built-in (Face ID, Windows Hello, etc.)
    CROSS_PLATFORM = 'cross-platform'  # Roaming (YubiKey, phone as authenticator)


class ResidentKeyRequirement(str, Enum):
    """
    Resident key (discoverable credential) requirement.

    Discoverable credentials allow passwordless login without
    providing username first.
    """
    REQUIRED = 'required'       # Must be discoverable
    PREFERRED = 'preferred'     # Prefer discoverable if supported
    DISCOURAGED = 'discouraged' # Don't make discoverable


class UserVerificationRequirement(str, Enum):
    """
    User verification requirement.

    Controls whether the authenticator must verify user identity
    (biometric, PIN, etc.) before signing.
    """
    REQUIRED = 'required'       # Must verify (recommended)
    PREFERRED = 'preferred'     # Verify if possible
    DISCOURAGED = 'discouraged' # Skip verification


class COSEAlgorithm(IntEnum):
    """
    COSE algorithm identifiers.

    These identify the cryptographic algorithms supported for
    credential key pairs.

    Reference: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    """
    # ECDSA algorithms (recommended)
    ES256 = -7      # ECDSA with P-256 and SHA-256 (most widely supported)
    ES384 = -35     # ECDSA with P-384 and SHA-384
    ES512 = -36     # ECDSA with P-521 and SHA-512

    # RSA algorithms
    RS256 = -257    # RSASSA-PKCS1-v1_5 with SHA-256
    RS384 = -258    # RSASSA-PKCS1-v1_5 with SHA-384
    RS512 = -259    # RSASSA-PKCS1-v1_5 with SHA-512

    # RSA-PSS algorithms
    PS256 = -37     # RSASSA-PSS with SHA-256
    PS384 = -38     # RSASSA-PSS with SHA-384
    PS512 = -39     # RSASSA-PSS with SHA-512

    # EdDSA
    EDDSA = -8      # EdDSA (Ed25519/Ed448)


class AuthenticatorTransport(str, Enum):
    """
    Authenticator transport hints.

    Indicates how the client can communicate with the authenticator.
    """
    USB = 'usb'             # USB connection
    NFC = 'nfc'             # NFC connection
    BLE = 'ble'             # Bluetooth Low Energy
    INTERNAL = 'internal'   # Platform authenticator (built-in)
    HYBRID = 'hybrid'       # Phone as authenticator (QR code + Bluetooth)


class ChallengeType(str, Enum):
    """Challenge types for registration and authentication"""
    REGISTRATION = 'registration'
    AUTHENTICATION = 'authentication'


class PasskeyFeatureFlags:
    """Feature flag keys within PASSKEY_FEATURES"""
    DISCOVERABLE_CREDENTIALS = 'DISCOVERABLE_CREDENTIALS'
    CROSS_ORIGIN = 'CROSS_ORIGIN'
    ATTESTATION_VERIFICATION = 'ATTESTATION_VERIFICATION'
    COUNTER_VALIDATION = 'COUNTER_VALIDATION'


class PasskeyErrorCodes:
    """Error codes for passkey operations"""
    NOT_ENABLED = 'PASSKEY_001'
    CHALLENGE_EXPIRED = 'PASSKEY_002'
    CHALLENGE_ALREADY_USED = 'PASSKEY_003'
    INVALID_ORIGIN = 'PASSKEY_004'
    INVALID_RP_ID = 'PASSKEY_005'
    CREDENTIAL_NOT_FOUND = 'PASSKEY_006'
    CREDENTIAL_REVOKED = 'PASSKEY_007'
    COUNTER_REGRESSION = 'PASSKEY_008'
    SIGNATURE_VERIFICATION_FAILED = 'PASSKEY_009'
    MAX_CREDENTIALS_REACHED = 'PASSKEY_010'
    ATTESTATION_VERIFICATION_FAILED = 'PASSKEY_011'
    RATE_LIMIT_EXCEEDED = 'PASSKEY_012'
    INVALID_CREDENTIAL_DATA = 'PASSKEY_013'
    USER_NOT_FOUND = 'PASSKEY_014'
    CREDENTIAL_ALREADY_EXISTS = 'PASSKEY_015'


# Default configuration values
PASSKEY_DEFAULTS = {
    PasskeyConfigKeys.ENABLED: False,
    PasskeyConfigKeys.RP_ID: None,  # Must be set by user
    PasskeyConfigKeys.RP_NAME: 'BlockAuth Application',
    PasskeyConfigKeys.ALLOWED_ORIGINS: [],
    PasskeyConfigKeys.ATTESTATION: AttestationConveyance.NONE.value,
    PasskeyConfigKeys.AUTHENTICATOR_ATTACHMENT: None,  # Allow any
    PasskeyConfigKeys.RESIDENT_KEY: ResidentKeyRequirement.PREFERRED.value,
    PasskeyConfigKeys.USER_VERIFICATION: UserVerificationRequirement.REQUIRED.value,
    PasskeyConfigKeys.REGISTRATION_TIMEOUT: 60000,  # 60 seconds
    PasskeyConfigKeys.AUTHENTICATION_TIMEOUT: 60000,
    PasskeyConfigKeys.CHALLENGE_LENGTH: 32,  # bytes
    PasskeyConfigKeys.CHALLENGE_EXPIRY: 300,  # 5 minutes
    PasskeyConfigKeys.SUPPORTED_ALGORITHMS: [
        COSEAlgorithm.ES256,  # Most widely supported
        COSEAlgorithm.RS256,  # Fallback for older authenticators
    ],
    PasskeyConfigKeys.MAX_CREDENTIALS_PER_USER: 10,
    PasskeyConfigKeys.STORAGE_BACKEND: 'django',
    PasskeyConfigKeys.RATE_LIMITS: {
        'registration_options': '10/hour',
        'registration_verify': '5/hour',
        'authentication_options': '20/minute',
        'authentication_verify': '10/minute',
    },
    PasskeyConfigKeys.FEATURES: {
        PasskeyFeatureFlags.DISCOVERABLE_CREDENTIALS: True,
        PasskeyFeatureFlags.CROSS_ORIGIN: False,
        PasskeyFeatureFlags.ATTESTATION_VERIFICATION: False,
        PasskeyFeatureFlags.COUNTER_VALIDATION: True,
    },
}
