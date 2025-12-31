"""
TOTP 2FA Configuration Management.

Provides centralized configuration for TOTP 2FA functionality
with Django settings integration.

Configuration is read from BLOCK_AUTH_SETTINGS["TOTP_CONFIG"].
"""
from dataclasses import dataclass, field
from typing import Optional

from ..settings import blockauth_settings
from .constants import (
    DEFAULTS,
    TOTP_CONFIG_KEY,
    TOTPAlgorithm,
    TOTPConfigKeys,
)


@dataclass
class TOTPConfiguration:
    """
    TOTP 2FA configuration container.

    All settings can be overridden via Django settings:
        BLOCK_AUTH_SETTINGS = {
            "TOTP_CONFIG": {
                "ISSUER_NAME": "MyApp",
                "DIGITS": 6,
                ...
            }
        }
    """

    # Core settings
    issuer_name: str = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.ISSUER_NAME])
    digits: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.DIGITS])
    time_step: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.TIME_STEP])
    algorithm: str = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.ALGORITHM])
    window: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.WINDOW])

    # Secret settings
    secret_length: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.SECRET_LENGTH])

    # Backup codes
    backup_codes_count: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.BACKUP_CODES_COUNT])
    backup_code_length: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.BACKUP_CODE_LENGTH])

    # Rate limiting
    max_attempts: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.MAX_ATTEMPTS])
    lockout_duration: int = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.LOCKOUT_DURATION])

    # Security
    require_confirmation: bool = field(default_factory=lambda: DEFAULTS[TOTPConfigKeys.REQUIRE_CONFIRMATION])

    def validate(self) -> None:
        """Validate configuration values."""
        if self.digits not in (6, 8):
            raise ValueError("TOTP digits must be 6 or 8")

        if self.time_step < 15 or self.time_step > 60:
            raise ValueError("TOTP time step must be between 15 and 60 seconds")

        if self.algorithm not in [a.value for a in TOTPAlgorithm]:
            raise ValueError(f"TOTP algorithm must be one of: {[a.value for a in TOTPAlgorithm]}")

        if self.secret_length < 16:
            raise ValueError("TOTP secret length must be at least 16 bytes (128 bits)")

        if self.window < 0 or self.window > 5:
            raise ValueError("TOTP window must be between 0 and 5")

        if self.backup_codes_count < 1 or self.backup_codes_count > 20:
            raise ValueError("Backup codes count must be between 1 and 20")

        if self.max_attempts < 3 or self.max_attempts > 10:
            raise ValueError("Max attempts must be between 3 and 10")


_config_instance: Optional[TOTPConfiguration] = None


def _get_totp_config_dict() -> dict:
    """
    Get the TOTP_CONFIG dict from settings.

    Returns:
        Dict with TOTP configuration, empty dict if not configured
    """
    return blockauth_settings.get(TOTP_CONFIG_KEY, {})


def get_totp_config() -> TOTPConfiguration:
    """
    Get the TOTP configuration instance.

    Loads configuration from Django settings TOTP_CONFIG on first call
    and caches the result.

    Returns:
        TOTPConfiguration instance with current settings
    """
    global _config_instance

    if _config_instance is None:
        _config_instance = _load_config_from_settings()

    return _config_instance


def _load_config_from_settings() -> TOTPConfiguration:
    """Load configuration from Django settings TOTP_CONFIG object."""
    totp_config = _get_totp_config_dict()

    config = TOTPConfiguration(
        issuer_name=totp_config.get(TOTPConfigKeys.ISSUER_NAME, DEFAULTS[TOTPConfigKeys.ISSUER_NAME]),
        digits=totp_config.get(TOTPConfigKeys.DIGITS, DEFAULTS[TOTPConfigKeys.DIGITS]),
        time_step=totp_config.get(TOTPConfigKeys.TIME_STEP, DEFAULTS[TOTPConfigKeys.TIME_STEP]),
        algorithm=totp_config.get(TOTPConfigKeys.ALGORITHM, DEFAULTS[TOTPConfigKeys.ALGORITHM]),
        window=totp_config.get(TOTPConfigKeys.WINDOW, DEFAULTS[TOTPConfigKeys.WINDOW]),
        secret_length=totp_config.get(TOTPConfigKeys.SECRET_LENGTH, DEFAULTS[TOTPConfigKeys.SECRET_LENGTH]),
        backup_codes_count=totp_config.get(
            TOTPConfigKeys.BACKUP_CODES_COUNT, DEFAULTS[TOTPConfigKeys.BACKUP_CODES_COUNT]
        ),
        backup_code_length=totp_config.get(
            TOTPConfigKeys.BACKUP_CODE_LENGTH, DEFAULTS[TOTPConfigKeys.BACKUP_CODE_LENGTH]
        ),
        max_attempts=totp_config.get(TOTPConfigKeys.MAX_ATTEMPTS, DEFAULTS[TOTPConfigKeys.MAX_ATTEMPTS]),
        lockout_duration=totp_config.get(
            TOTPConfigKeys.LOCKOUT_DURATION, DEFAULTS[TOTPConfigKeys.LOCKOUT_DURATION]
        ),
        require_confirmation=totp_config.get(
            TOTPConfigKeys.REQUIRE_CONFIRMATION, DEFAULTS[TOTPConfigKeys.REQUIRE_CONFIRMATION]
        ),
    )

    config.validate()
    return config


def reset_config() -> None:
    """Reset the cached configuration. Useful for testing."""
    global _config_instance
    _config_instance = None
