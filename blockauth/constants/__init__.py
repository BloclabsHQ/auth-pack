"""
Constants package for blockauth

This package contains all constants used throughout the BlockAuth package.
Constants are organized into logical modules for better maintainability.

Available modules:
- core: Core constants (Features, ConfigKeys, ErrorMessages, URLNames, SocialProviders)
- sensitive_fields: Sensitive data redaction constants

Usage:
    from blockauth.constants import Features, ConfigKeys, SENSITIVE_FIELDS
    from blockauth.constants.core import Features
    from blockauth.constants.sensitive_fields import SENSITIVE_FIELDS
"""

# Import core constants
from .core import (
    Features,
    SocialProviders, 
    ConfigKeys,
    ErrorMessages,
    URLNames
)

# Import sensitive fields constants
from .sensitive_fields import SENSITIVE_FIELDS, SENSITIVE_PATTERNS, REDACTION_STRING

__all__ = [
    # Core constants
    'Features',
    'SocialProviders',
    'ConfigKeys', 
    'ErrorMessages',
    'URLNames',
    # Sensitive fields constants
    'SENSITIVE_FIELDS',
    'SENSITIVE_PATTERNS', 
    'REDACTION_STRING'
]
