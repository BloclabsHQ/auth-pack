"""
BlockAuth Enums - Django-independent enum definitions.

These enums are defined separately from Django models to avoid AppRegistryNotReady
errors when importing them before Django apps are fully loaded.

They are compatible with Django's TextChoices/IntegerChoices for use in model fields.
"""

from enum import Enum


class AuthenticationType(str, Enum):
    """
    Authentication methods supported by BlockAuth.

    This is a str+Enum hybrid that's compatible with Django's TextChoices
    but doesn't require Django's app registry to be ready.

    Usage in models:
        authentication_type = models.CharField(
            max_length=20,
            choices=[(e.value, e.label) for e in AuthenticationType]
        )

    Usage in code:
        if auth_type == AuthenticationType.EMAIL:
            ...
    """

    EMAIL = "EMAIL"
    WALLET = "WALLET"
    GOOGLE = "GOOGLE"
    FACEBOOK = "FACEBOOK"
    LINKEDIN = "LINKEDIN"
    APPLE = "APPLE"
    PASSWORDLESS = "PASSWORDLESS"

    @property
    def label(self) -> str:
        """Human-readable label for the authentication type."""
        labels = {
            "EMAIL": "Email",
            "WALLET": "Wallet",
            "GOOGLE": "Google",
            "FACEBOOK": "Facebook",
            "LINKEDIN": "LinkedIn",
            "APPLE": "Apple",
            "PASSWORDLESS": "Passwordless",
        }
        return labels.get(self.value, self.value)

    @classmethod
    def choices(cls) -> list:
        """Django-compatible choices tuple list."""
        return [(e.value, e.label) for e in cls]
