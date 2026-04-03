"""
TOTP 2FA Storage Layer

Provides pluggable storage backends for TOTP 2FA data.
"""

from .base import ITOTP2FAStore, TOTP2FAData
from .django_storage import DjangoTOTP2FAStore

__all__ = [
    "ITOTP2FAStore",
    "TOTP2FAData",
    "DjangoTOTP2FAStore",
]
