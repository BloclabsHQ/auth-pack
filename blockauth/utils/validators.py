"""
BlockAuth Validators
====================
Common validation utilities for BlockAuth.

This module contains validators for:
- Phone numbers
- Passwords

Password Requirements:
- 8-128 characters
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 number (0-9)
- At least 1 symbol (!@#$%^&*()_+-=[]{};\':\"\\|,.<>/?)

Usage:
    from blockauth.utils.validators import validate_password, is_valid_password

    # Get list of errors
    errors = validate_password("MyPassword123!")
    if errors:
        print(errors)

    # Quick boolean check
    if is_valid_password("MyPassword123!"):
        print("Valid!")

Django Integration:
    # settings.py
    AUTH_PASSWORD_VALIDATORS = [
        {'NAME': 'blockauth.utils.validators.BlockAuthPasswordValidator'},
    ]
"""

import re
from typing import List

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

# =============================================================================
# PASSWORD VALIDATION CONSTANTS
# =============================================================================

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
PASSWORD_SYMBOLS = r"!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?"

# Standard error message for invalid passwords (platform-wide)
PASSWORD_VALIDATION_ERROR = (
    "Password must be 8-128 characters and contain at least one uppercase letter, "
    "one lowercase letter, one number, and one symbol (!@#$%^&*)."
)


# =============================================================================
# PASSWORD VALIDATION FUNCTIONS
# =============================================================================


def validate_password(password: str) -> List[str]:
    """
    Validate password against BlockAuth requirements.

    Args:
        password: The password string to validate.

    Returns:
        List of error messages. Empty list means password is valid.

    Example:
        >>> validate_password("weak")
        ['Password must be 8-128 characters and contain...']
        >>> validate_password("StrongPass1!")
        []
    """
    # Check all requirements
    is_valid = (
        len(password) >= PASSWORD_MIN_LENGTH
        and len(password) <= PASSWORD_MAX_LENGTH
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(rf"[{PASSWORD_SYMBOLS}]", password)
    )

    if is_valid:
        return []

    return [PASSWORD_VALIDATION_ERROR]


def is_valid_password(password: str) -> bool:
    """
    Quick check if password meets BlockAuth requirements.

    Args:
        password: The password string to validate.

    Returns:
        True if valid, False otherwise.

    Example:
        >>> is_valid_password("weak")
        False
        >>> is_valid_password("StrongPass1!")
        True
    """
    return len(validate_password(password)) == 0


# =============================================================================
# DJANGO PASSWORD VALIDATOR CLASS
# =============================================================================


class BlockAuthPasswordValidator:
    """
    Django password validator implementing BlockAuth requirements.

    Add to AUTH_PASSWORD_VALIDATORS in settings.py:
        {'NAME': 'blockauth.utils.validators.BlockAuthPasswordValidator'}

    Requirements:
        - 8-128 characters
        - At least 1 uppercase letter (A-Z)
        - At least 1 lowercase letter (a-z)
        - At least 1 number (0-9)
        - At least 1 symbol (!@#$%^&*()_+-=[]{};\':\"\\|,.<>/?)
    """

    def validate(self, password: str, user=None) -> None:
        """
        Validate password. Raises ValidationError if invalid.

        Args:
            password: The password to validate.
            user: Optional user instance (unused, for Django compatibility).

        Raises:
            ValidationError: If password doesn't meet requirements.
        """
        errors = validate_password(password)
        if errors:
            raise ValidationError(errors)

    def get_help_text(self) -> str:
        """Return help text describing password requirements."""
        return _(PASSWORD_VALIDATION_ERROR)


# =============================================================================
# REGEX PATTERN (for use in other systems)
# =============================================================================

PASSWORD_REGEX_PATTERN = (
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)"
    rf"(?=.*[{PASSWORD_SYMBOLS}])"
    rf".{{{PASSWORD_MIN_LENGTH},{PASSWORD_MAX_LENGTH}}}$"
)


# =============================================================================
# PHONE NUMBER VALIDATION
# =============================================================================


def is_valid_phone_number(phone: str) -> bool:
    """
    Validate international phone number format.

    Args:
        phone: Phone number string to validate.

    Returns:
        True if valid international phone number, False otherwise.

    Example:
        >>> is_valid_phone_number("+1234567890")
        False  # Too short
        >>> is_valid_phone_number("+12345678901")
        True
    """
    # Remove spaces, dashes, and parentheses
    phone = re.sub(r"[()\s-]", "", phone)
    pattern = re.compile(r"^\+?\d{10,15}$")

    if not pattern.match(phone):
        return False

    # Only international phone numbers are allowed
    return phone.startswith("+") and 11 <= len(phone) <= 15
