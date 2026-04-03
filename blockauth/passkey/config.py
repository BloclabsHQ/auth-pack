"""
Passkey Configuration Manager for BlockAuth

Handles loading and validating passkey configuration from BLOCK_AUTH_SETTINGS.

Configuration is read from BLOCK_AUTH_SETTINGS["PASSKEY_CONFIG"].
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional

from .constants import (
    PASSKEY_CONFIG_KEY,
    PASSKEY_DEFAULTS,
    AttestationConveyance,
    AuthenticatorAttachment,
    COSEAlgorithm,
    PasskeyConfigKeys,
    PasskeyFeatureFlags,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from .exceptions import ConfigurationError


@dataclass
class PasskeyConfiguration:
    """
    Passkey configuration dataclass.

    Holds all configuration values with validation.
    """

    # Relying Party
    rp_id: str
    rp_name: str
    allowed_origins: List[str]

    # Attestation
    attestation: str

    # Authenticator preferences
    authenticator_attachment: Optional[str]
    resident_key: str
    user_verification: str

    # Timeouts (milliseconds)
    registration_timeout: int
    authentication_timeout: int

    # Challenge
    challenge_length: int
    challenge_expiry: int  # seconds

    # Algorithms
    supported_algorithms: List[int]

    # Limits
    max_credentials_per_user: int

    # Storage
    storage_backend: str

    # Rate limits
    rate_limits: dict

    # Feature flags
    features: dict = field(default_factory=dict)

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature flag is enabled"""
        return self.features.get(feature, False)

    @property
    def discoverable_credentials_enabled(self) -> bool:
        """Check if discoverable credentials are enabled"""
        return self.is_feature_enabled(PasskeyFeatureFlags.DISCOVERABLE_CREDENTIALS)

    @property
    def cross_origin_enabled(self) -> bool:
        """Check if cross-origin requests are enabled"""
        return self.is_feature_enabled(PasskeyFeatureFlags.CROSS_ORIGIN)

    @property
    def attestation_verification_enabled(self) -> bool:
        """Check if attestation verification is enabled"""
        return self.is_feature_enabled(PasskeyFeatureFlags.ATTESTATION_VERIFICATION)

    @property
    def counter_validation_enabled(self) -> bool:
        """Check if counter validation is enabled"""
        return self.is_feature_enabled(PasskeyFeatureFlags.COUNTER_VALIDATION)


class PasskeyConfigManager:
    """
    Manages passkey configuration loading and validation.

    Reads from Django's BLOCK_AUTH_SETTINGS["PASSKEY_CONFIG"] and provides
    a validated PasskeyConfiguration object.
    """

    _instance: Optional["PasskeyConfigManager"] = None
    _config: Optional[PasskeyConfiguration] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _get_passkey_config_dict(self) -> dict:
        """Get the PASSKEY_CONFIG dict from settings"""
        try:
            from django.conf import settings

            block_auth_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {})
            return block_auth_settings.get(PASSKEY_CONFIG_KEY, {})
        except ImportError:
            return {}

    def _get_with_default(self, key: str, passkey_config: dict) -> Any:
        """Get setting from PASSKEY_CONFIG with default from PASSKEY_DEFAULTS"""
        default = PASSKEY_DEFAULTS.get(key)
        return passkey_config.get(key, default)

    def get_config(self, force_reload: bool = False) -> PasskeyConfiguration:
        """
        Get passkey configuration.

        Args:
            force_reload: Force reload from settings

        Returns:
            PasskeyConfiguration object

        Raises:
            ConfigurationError: If configuration is invalid
        """
        if self._config is not None and not force_reload:
            return self._config

        self._config = self._load_config()
        return self._config

    def _load_config(self) -> PasskeyConfiguration:
        """Load and validate configuration from settings"""

        # Get the PASSKEY_CONFIG object
        passkey_config = self._get_passkey_config_dict()

        # Get RP ID (required)
        rp_id = self._get_with_default(PasskeyConfigKeys.RP_ID, passkey_config)
        if not rp_id:
            raise ConfigurationError("PASSKEY_CONFIG.RP_ID is required. Set it to your domain (e.g., 'example.com')")

        # Get RP name
        rp_name = self._get_with_default(PasskeyConfigKeys.RP_NAME, passkey_config)

        # Get allowed origins
        allowed_origins = self._get_with_default(PasskeyConfigKeys.ALLOWED_ORIGINS, passkey_config)
        if not allowed_origins:
            # Auto-generate from RP ID if not set
            allowed_origins = [f"https://{rp_id}"]

        # Validate allowed origins format
        for origin in allowed_origins:
            if not origin.startswith(("http://", "https://")):
                raise ConfigurationError(f"Invalid origin '{origin}'. Origins must start with http:// or https://")

        # Get and validate attestation
        attestation = self._get_with_default(PasskeyConfigKeys.ATTESTATION, passkey_config)
        valid_attestations = [a.value for a in AttestationConveyance]
        if attestation not in valid_attestations:
            raise ConfigurationError(
                f"Invalid PASSKEY_CONFIG.ATTESTATION '{attestation}'. " f"Valid values: {valid_attestations}"
            )

        # Get authenticator attachment (can be None)
        authenticator_attachment = self._get_with_default(PasskeyConfigKeys.AUTHENTICATOR_ATTACHMENT, passkey_config)
        if authenticator_attachment is not None:
            valid_attachments = [a.value for a in AuthenticatorAttachment]
            if authenticator_attachment not in valid_attachments:
                raise ConfigurationError(
                    f"Invalid PASSKEY_CONFIG.AUTHENTICATOR_ATTACHMENT '{authenticator_attachment}'. "
                    f"Valid values: {valid_attachments} or None"
                )

        # Get and validate resident key requirement
        resident_key = self._get_with_default(PasskeyConfigKeys.RESIDENT_KEY, passkey_config)
        valid_resident_keys = [r.value for r in ResidentKeyRequirement]
        if resident_key not in valid_resident_keys:
            raise ConfigurationError(
                f"Invalid PASSKEY_CONFIG.RESIDENT_KEY '{resident_key}'. " f"Valid values: {valid_resident_keys}"
            )

        # Get and validate user verification
        user_verification = self._get_with_default(PasskeyConfigKeys.USER_VERIFICATION, passkey_config)
        valid_user_verifications = [u.value for u in UserVerificationRequirement]
        if user_verification not in valid_user_verifications:
            raise ConfigurationError(
                f"Invalid PASSKEY_CONFIG.USER_VERIFICATION '{user_verification}'. "
                f"Valid values: {valid_user_verifications}"
            )

        # Get timeouts
        registration_timeout = self._get_with_default(PasskeyConfigKeys.REGISTRATION_TIMEOUT, passkey_config)
        authentication_timeout = self._get_with_default(PasskeyConfigKeys.AUTHENTICATION_TIMEOUT, passkey_config)

        if not isinstance(registration_timeout, int) or registration_timeout <= 0:
            raise ConfigurationError("PASSKEY_CONFIG.REGISTRATION_TIMEOUT must be a positive integer")
        if not isinstance(authentication_timeout, int) or authentication_timeout <= 0:
            raise ConfigurationError("PASSKEY_CONFIG.AUTHENTICATION_TIMEOUT must be a positive integer")

        # Get challenge settings
        challenge_length = self._get_with_default(PasskeyConfigKeys.CHALLENGE_LENGTH, passkey_config)
        challenge_expiry = self._get_with_default(PasskeyConfigKeys.CHALLENGE_EXPIRY, passkey_config)

        if not isinstance(challenge_length, int) or challenge_length < 16:
            raise ConfigurationError("PASSKEY_CONFIG.CHALLENGE_LENGTH must be at least 16 bytes")
        if not isinstance(challenge_expiry, int) or challenge_expiry <= 0:
            raise ConfigurationError("PASSKEY_CONFIG.CHALLENGE_EXPIRY must be a positive integer")

        # Get and validate algorithms
        supported_algorithms = self._get_with_default(PasskeyConfigKeys.SUPPORTED_ALGORITHMS, passkey_config)
        valid_algorithms = [a.value for a in COSEAlgorithm]
        for alg in supported_algorithms:
            if alg not in valid_algorithms:
                raise ConfigurationError(
                    f"Invalid algorithm {alg} in PASSKEY_CONFIG.SUPPORTED_ALGORITHMS. "
                    f"Valid values: {valid_algorithms}"
                )

        # Get limits
        max_credentials = self._get_with_default(PasskeyConfigKeys.MAX_CREDENTIALS_PER_USER, passkey_config)
        if not isinstance(max_credentials, int) or max_credentials <= 0:
            raise ConfigurationError("PASSKEY_CONFIG.MAX_CREDENTIALS_PER_USER must be a positive integer")

        # Get storage backend
        storage_backend = self._get_with_default(PasskeyConfigKeys.STORAGE_BACKEND, passkey_config)
        valid_backends = ["django", "memory"]
        if storage_backend not in valid_backends:
            raise ConfigurationError(
                f"Invalid PASSKEY_CONFIG.STORAGE_BACKEND '{storage_backend}'. " f"Valid values: {valid_backends}"
            )

        # Get rate limits
        rate_limits = self._get_with_default(PasskeyConfigKeys.RATE_LIMITS, passkey_config)

        # Get feature flags
        features = self._get_with_default(PasskeyConfigKeys.FEATURES, passkey_config)

        return PasskeyConfiguration(
            rp_id=rp_id,
            rp_name=rp_name,
            allowed_origins=allowed_origins,
            attestation=attestation,
            authenticator_attachment=authenticator_attachment,
            resident_key=resident_key,
            user_verification=user_verification,
            registration_timeout=registration_timeout,
            authentication_timeout=authentication_timeout,
            challenge_length=challenge_length,
            challenge_expiry=challenge_expiry,
            supported_algorithms=supported_algorithms,
            max_credentials_per_user=max_credentials,
            storage_backend=storage_backend,
            rate_limits=rate_limits,
            features=features,
        )

    def reload(self):
        """Force reload configuration from settings"""
        self._config = None
        return self.get_config(force_reload=True)


# Singleton instance
_config_manager = PasskeyConfigManager()


def get_passkey_config(force_reload: bool = False) -> PasskeyConfiguration:
    """
    Get passkey configuration.

    Args:
        force_reload: Force reload from settings

    Returns:
        PasskeyConfiguration object
    """
    return _config_manager.get_config(force_reload=force_reload)


def reload_passkey_config() -> PasskeyConfiguration:
    """Reload passkey configuration from settings"""
    return _config_manager.reload()
