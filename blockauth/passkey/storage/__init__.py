"""
Passkey Storage Module

Provides storage backends for passkey credentials.
"""

from .base import ICredentialStore
from .django_storage import DjangoCredentialStore
from .memory_storage import MemoryCredentialStore

__all__ = [
    'ICredentialStore',
    'DjangoCredentialStore',
    'MemoryCredentialStore',
]
