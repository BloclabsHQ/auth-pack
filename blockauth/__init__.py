"""
BlockAuth - Reusable Authentication Components.

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

default_app_config = 'blockauth.apps.BlockAuthConfig'

# =============================================================================
# TOTP Components
# =============================================================================

# Service with static utility methods
from .totp.services.totp_service import (
    TOTPService,
    ISecretEncryption,
    SetupResult as TOTPSetupResult,
    VerifyResult as TOTPVerifyResult,
)

# Storage interface - implement this for custom storage
from .totp.storage.base import ITOTP2FAStore, TOTP2FAData

# =============================================================================
# Passkey Components
# =============================================================================

# Service
from .passkey.services.passkey_service import (
    PasskeyService,
    RegistrationResult as PasskeyRegistrationResult,
    AuthenticationResult as PasskeyAuthenticationResult,
)

# Storage interface - implement this for custom storage
from .passkey.storage.base import ICredentialStore, CredentialData

# Challenge service
from .passkey.services.challenge_service import ChallengeService

# =============================================================================
# KDF (Optional)
# =============================================================================
# KDF is optional and must be explicitly enabled
# Use blockauth.kdf.is_enabled() to check if KDF is available
# Use blockauth.kdf.get_kdf_service() to get the service when needed

__all__ = [
    # TOTP
    'TOTPService',
    'ISecretEncryption',
    'ITOTP2FAStore',
    'TOTP2FAData',
    'TOTPSetupResult',
    'TOTPVerifyResult',

    # Passkey
    'PasskeyService',
    'ICredentialStore',
    'CredentialData',
    'PasskeyRegistrationResult',
    'PasskeyAuthenticationResult',
    'ChallengeService',
]
