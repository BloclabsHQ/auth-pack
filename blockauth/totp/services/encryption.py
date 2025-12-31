"""
TOTP Secret Encryption Service

Provides Fernet-based encryption for TOTP secrets.
Secrets are encrypted at rest to comply with security standards.

Security: Uses AES-256 encryption via cryptography library's Fernet.

Configuration:
    BLOCK_AUTH_SETTINGS = {
        "FEATURES": {"TOTP_2FA": True},
        "TOTP_CONFIG": {
            "ENCRYPTION_KEY": "your-fernet-key",  # REQUIRED
        }
    }
"""
import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from blockauth.utils.logger import blockauth_logger
from .totp_service import ISecretEncryption

logger = logging.getLogger(__name__)


class FernetSecretEncryption(ISecretEncryption):
    """
    Fernet-based encryption for TOTP secrets.

    Uses AES-256-CBC with HMAC for authenticated encryption.
    Keys are derived from a master key using PBKDF2.

    Usage:
        from blockauth.totp.services.encryption import FernetSecretEncryption

        encryption = FernetSecretEncryption(master_key="your-32-byte-base64-key")

        # Encrypt a secret
        encrypted = encryption.encrypt("JBSWY3DPEHPK3PXP")

        # Decrypt a secret
        decrypted = encryption.decrypt(encrypted)
    """

    # Salt for key derivation (static but adds entropy)
    _SALT = b'blockauth-totp-encryption-v1'

    def __init__(self, master_key: str):
        """
        Initialize encryption service with master key.

        Args:
            master_key: Base64-encoded 32-byte key, or a passphrase
                       that will be derived into a Fernet key.

        Raises:
            ValueError: If master_key is empty or invalid
        """
        if not master_key:
            raise ValueError("Encryption master key is required")

        self._fernet = self._create_fernet(master_key)
        blockauth_logger.debug("TOTP encryption service initialized")

    def _create_fernet(self, master_key: str) -> Fernet:
        """
        Create Fernet instance from master key.

        If the key is already a valid Fernet key (44 base64 chars),
        use it directly. Otherwise, derive a key using PBKDF2.

        Args:
            master_key: Master key string

        Returns:
            Fernet instance
        """
        # Try to use as-is if it's already a valid Fernet key
        if len(master_key) == 44:
            try:
                return Fernet(master_key.encode())
            except Exception:
                pass  # Fall through to key derivation

        # Derive a Fernet key from the master key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._SALT,
            iterations=100_000,
        )

        derived_key = kdf.derive(master_key.encode())
        fernet_key = base64.urlsafe_b64encode(derived_key)

        return Fernet(fernet_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a TOTP secret.

        Args:
            plaintext: Base32-encoded TOTP secret

        Returns:
            Base64-encoded encrypted secret

        Raises:
            ValueError: If plaintext is empty
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty secret")

        try:
            encrypted_bytes = self._fernet.encrypt(plaintext.encode('utf-8'))
            return encrypted_bytes.decode('utf-8')
        except Exception as e:
            blockauth_logger.error(
                "TOTP secret encryption failed",
                {"error": str(e)[:100]}
            )
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a TOTP secret.

        Args:
            ciphertext: Base64-encoded encrypted secret

        Returns:
            Decrypted Base32-encoded TOTP secret

        Raises:
            ValueError: If decryption fails (invalid key, corrupted data, etc.)
        """
        if not ciphertext:
            raise ValueError("Cannot decrypt empty ciphertext")

        try:
            decrypted_bytes = self._fernet.decrypt(ciphertext.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except InvalidToken:
            blockauth_logger.error(
                "TOTP secret decryption failed - invalid token (wrong key or corrupted data)"
            )
            raise ValueError("Decryption failed: invalid token")
        except Exception as e:
            blockauth_logger.error(
                "TOTP secret decryption failed",
                {"error": str(e)[:100]}
            )
            raise ValueError(f"Decryption failed: {e}")


class TOTPEncryptionNotConfiguredError(Exception):
    """
    Raised when TOTP encryption is not properly configured.

    This is a configuration error that should be caught during startup.
    TOTP secrets MUST be encrypted - there is no fallback to plaintext.
    """

    def __init__(self, message: str = None):
        default_message = (
            "ENCRYPTION_KEY is not configured in TOTP_CONFIG. "
            "TOTP 2FA requires encryption for secure secret storage. "
            "Generate a key with: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        )
        super().__init__(message or default_message)


def get_encryption_service(raise_if_missing: bool = True) -> Optional[FernetSecretEncryption]:
    """
    Get the TOTP encryption service from Django settings.

    Reads the encryption key from BLOCK_AUTH_SETTINGS['TOTP_CONFIG']['ENCRYPTION_KEY'].

    Args:
        raise_if_missing: If True (default), raises exception when key not configured.
                         If False, returns None (for validation checks only).

    Returns:
        FernetSecretEncryption instance

    Raises:
        TOTPEncryptionNotConfiguredError: If key is not configured and raise_if_missing=True
        ValueError: If key is configured but invalid
    """
    from blockauth.settings import blockauth_settings
    from ..constants import TOTP_CONFIG_KEY, TOTPConfigKeys

    # Get TOTP_CONFIG object
    totp_config = blockauth_settings.get(TOTP_CONFIG_KEY, {})
    encryption_key = totp_config.get(TOTPConfigKeys.ENCRYPTION_KEY)

    if not encryption_key:
        if raise_if_missing:
            blockauth_logger.error(
                "SECURITY: TOTP_CONFIG.ENCRYPTION_KEY not configured - TOTP cannot be used safely"
            )
            raise TOTPEncryptionNotConfiguredError()
        return None

    return FernetSecretEncryption(master_key=encryption_key)


def validate_totp_encryption_config() -> bool:
    """
    Validate TOTP encryption configuration at startup.

    Call this during Django app initialization to catch configuration
    errors early rather than at runtime.

    Returns:
        True if encryption is properly configured

    Raises:
        TOTPEncryptionNotConfiguredError: If encryption key is missing
        ValueError: If encryption key is invalid

    Usage in Django AppConfig:
        class TOTPConfig(AppConfig):
            def ready(self):
                from blockauth.totp.services.encryption import validate_totp_encryption_config
                validate_totp_encryption_config()
    """
    from blockauth.totp import is_enabled
    from blockauth.settings import blockauth_settings
    from ..constants import TOTP_CONFIG_KEY, TOTPConfigKeys

    # Check if TOTP is enabled (via FEATURES["TOTP_2FA"])
    if not is_enabled():
        # TOTP disabled, no need to validate encryption
        return True

    # TOTP is enabled, encryption MUST be configured
    totp_config = blockauth_settings.get(TOTP_CONFIG_KEY, {})
    encryption_key = totp_config.get(TOTPConfigKeys.ENCRYPTION_KEY)

    if not encryption_key:
        raise TOTPEncryptionNotConfiguredError(
            "TOTP is enabled (FEATURES['TOTP_2FA']=True) but TOTP_CONFIG.ENCRYPTION_KEY is not configured. "
            "Either disable TOTP or configure an encryption key. "
            "Generate a key with: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        )

    # Validate the key works by creating an instance
    try:
        service = FernetSecretEncryption(master_key=encryption_key)
        # Test encrypt/decrypt
        test_data = "totp-config-validation-test"
        decrypted = service.decrypt(service.encrypt(test_data))
        if decrypted != test_data:
            raise ValueError("Encryption roundtrip failed")
    except Exception as e:
        raise ValueError(
            f"TOTP_CONFIG.ENCRYPTION_KEY is invalid: {e}. "
            "Generate a new key with: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        )

    blockauth_logger.info("TOTP encryption configuration validated successfully")
    return True
