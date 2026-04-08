"""
Feature flag utilities for BlockAuth.

This module provides utilities to check if specific authentication features
are enabled based on the BLOCK_AUTH_SETTINGS configuration.
"""

from blockauth.conf import auth_settings
from blockauth.constants import ConfigKeys, Features


def is_feature_enabled(feature_name: str) -> bool:
    """
    Check if a specific feature is enabled.

    Args:
        feature_name (str): Name of the feature to check (use Features constants)

    Returns:
        bool: True if the feature is enabled, False otherwise

    Example:
        >>> is_feature_enabled(Features.SIGNUP)
        True
        >>> is_feature_enabled(Features.EMAIL_CHANGE)
        False
    """
    features = getattr(auth_settings, ConfigKeys.FEATURES, {})
    return features.get(feature_name, True)  # Default to True for backward compatibility


def get_enabled_features() -> dict:
    """
    Get all feature flags and their current status.

    Returns:
        dict: Dictionary of feature names and their enabled status

    Example:
        >>> get_enabled_features()
        {
            'SIGNUP': True,
            'BASIC_LOGIN': True,
            'EMAIL_CHANGE': False,
            ...
        }
    """
    return getattr(auth_settings, ConfigKeys.FEATURES, {})


def validate_feature_configuration() -> list:
    """
    Validate the feature configuration and return any issues.

    Returns:
        list: List of validation issues (empty if configuration is valid)

    Example:
        >>> validate_feature_configuration()
        []
        >>> validate_feature_configuration()
        ['EMAIL_CHANGE is enabled but EMAIL_VERIFICATION is disabled']
    """
    issues = []
    features = get_enabled_features()

    # Check for logical dependencies
    if features.get(Features.EMAIL_CHANGE, True) and not features.get(Features.EMAIL_VERIFICATION, True):
        issues.append(f"{Features.EMAIL_CHANGE} is enabled but {Features.EMAIL_VERIFICATION} is disabled")

    if features.get(Features.PASSWORDLESS_LOGIN, True) and not features.get(Features.SIGNUP, True):
        issues.append(f"{Features.PASSWORDLESS_LOGIN} is enabled but {Features.SIGNUP} is disabled")

    return issues


def get_feature_documentation() -> dict:
    """
    Get documentation for all available features.

    Returns:
        dict: Dictionary of feature names and their descriptions
    """
    return {
        Features.SIGNUP: "Enable user registration with email and password",
        Features.BASIC_LOGIN: "Enable email/password login authentication",
        Features.PASSWORDLESS_LOGIN: "Enable passwordless login with OTP",
        Features.WALLET_LOGIN: "Enable wallet-based authentication",
        Features.TOKEN_REFRESH: "Enable JWT token refresh functionality",
        Features.PASSWORD_RESET: "Enable password reset functionality",
        Features.PASSWORD_CHANGE: "Enable password change for authenticated users",
        Features.EMAIL_CHANGE: "Enable email change functionality",
        Features.EMAIL_VERIFICATION: "Enable email verification requirement",
        Features.WALLET_EMAIL_ADD: "Enable adding email to wallet accounts",
        Features.SOCIAL_AUTH: "Master switch for social authentication",
    }
