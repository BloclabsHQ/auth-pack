"""
BlockAuth - Reusable Authentication Components.

:copyright: (c) BloclabsHQ
:license: MIT

Quick usage for B2B2C (custom storage):
    from blockauth import TOTPService, ITOTP2FAStore, TOTP2FAData, ISecretEncryption

    class MyStore(ITOTP2FAStore):
        # Implement for your model (e.g., ConsumerTOTP)
        pass

    service = TOTPService(store=MyStore(), encryption_service=my_encryption)

Quick usage for B2C (Django User):
    from blockauth.totp.storage.django_storage import DjangoTOTP2FAStore
    from blockauth import TOTPService

    service = TOTPService(store=DjangoTOTP2FAStore())

Static utilities (no storage needed):
    from blockauth import TOTPService

    secret = TOTPService.generate_secret()
    code, counter = TOTPService.generate_totp(secret)
    is_valid, counter = TOTPService.verify_totp(secret, user_code)
    backup_codes = TOTPService.generate_backup_codes()
"""

__version__ = "0.16.2"

# =============================================================================
# Direct imports (Django-independent, no AppRegistryNotReady errors)
# =============================================================================
from blockauth.enums import AuthenticationType

# =============================================================================
# Lazy imports to avoid AppRegistryNotReady errors
# =============================================================================
# Django models can't be imported until apps are ready, so we use lazy loading

__all__ = [
    # Enums (Django-independent)
    "AuthenticationType",
    # TOTP
    "TOTPService",
    "ISecretEncryption",
    "ITOTP2FAStore",
    "TOTP2FAData",
    "TOTPSetupResult",
    "TOTPVerifyResult",
    # Passkey
    "PasskeyService",
    "ICredentialStore",
    "CredentialData",
    "PasskeyRegistrationResult",
    "PasskeyAuthenticationResult",
    "ChallengeService",
    # Step-Up Authentication (RFC 9470)
    "ReceiptIssuer",
    "ReceiptValidator",
    "ReceiptClaims",
    "ReceiptValidationError",
]


def __getattr__(name):
    """
    Lazy import to avoid Django AppRegistryNotReady errors.

    This allows 'from blockauth import TOTPService' to work after Django apps are loaded.
    """
    # TOTP components
    if name == "TOTPService":
        from .totp.services.totp_service import TOTPService

        return TOTPService
    if name == "ISecretEncryption":
        from .totp.services.totp_service import ISecretEncryption

        return ISecretEncryption
    if name == "TOTPSetupResult":
        from .totp.services.totp_service import SetupResult

        return SetupResult
    if name == "TOTPVerifyResult":
        from .totp.services.totp_service import VerifyResult

        return VerifyResult
    if name == "ITOTP2FAStore":
        from .totp.storage.base import ITOTP2FAStore

        return ITOTP2FAStore
    if name == "TOTP2FAData":
        from .totp.storage.base import TOTP2FAData

        return TOTP2FAData

    # Passkey components
    if name == "PasskeyService":
        from .passkey.services.passkey_service import PasskeyService

        return PasskeyService
    if name == "PasskeyRegistrationResult":
        from .passkey.services.passkey_service import RegistrationResult

        return RegistrationResult
    if name == "PasskeyAuthenticationResult":
        from .passkey.services.passkey_service import AuthenticationResult

        return AuthenticationResult
    if name == "ICredentialStore":
        from .passkey.storage.base import ICredentialStore

        return ICredentialStore
    if name == "CredentialData":
        from .passkey.storage.base import CredentialData

        return CredentialData
    if name == "ChallengeService":
        from .passkey.services.challenge_service import ChallengeService

        return ChallengeService

    # Step-Up Authentication components (Django-independent — no lazy loading needed)
    if name == "ReceiptIssuer":
        from .stepup.receipt import ReceiptIssuer

        return ReceiptIssuer
    if name == "ReceiptValidator":
        from .stepup.receipt import ReceiptValidator

        return ReceiptValidator
    if name == "ReceiptClaims":
        from .stepup.receipt import ReceiptClaims

        return ReceiptClaims
    if name == "ReceiptValidationError":
        from .stepup.receipt import ReceiptValidationError

        return ReceiptValidationError

    raise AttributeError(f"module 'blockauth' has no attribute '{name}'")
