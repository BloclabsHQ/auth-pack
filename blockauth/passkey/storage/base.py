"""
Abstract Storage Interface for Passkey Credentials

Defines the interface that all credential storage backends must implement.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CredentialData:
    """
    Data transfer object for passkey credentials.

    This is used to transfer credential data between storage backends
    and the passkey service, providing a consistent interface regardless
    of the storage implementation.
    """
    id: str
    user_id: Any  # Can be int, str, UUID depending on user model
    credential_id: str  # Base64URL encoded
    public_key: str  # Base64URL encoded COSE key
    algorithm: int  # COSE algorithm identifier
    sign_count: int
    aaguid: str = ''
    name: str = ''
    transports: List[str] = field(default_factory=list)
    authenticator_attachment: str = ''
    backup_eligible: bool = False
    backup_state: bool = False
    is_discoverable: bool = False
    user_handle: str = ''
    attestation_object: str = ''
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'credential_id': self.credential_id,
            'public_key': self.public_key,
            'algorithm': self.algorithm,
            'sign_count': self.sign_count,
            'aaguid': self.aaguid,
            'name': self.name,
            'transports': self.transports,
            'authenticator_attachment': self.authenticator_attachment,
            'backup_eligible': self.backup_eligible,
            'backup_state': self.backup_state,
            'is_discoverable': self.is_discoverable,
            'user_handle': self.user_handle,
            'attestation_object': self.attestation_object,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'is_active': self.is_active,
        }


class ICredentialStore(ABC):
    """
    Abstract interface for credential storage.

    All storage backends (Django ORM, Memory, Redis, etc.) must implement
    this interface to ensure consistent behavior across implementations.
    """

    @abstractmethod
    def save(self, credential: CredentialData) -> CredentialData:
        """
        Save a new credential.

        Args:
            credential: Credential data to save

        Returns:
            Saved credential with generated ID

        Raises:
            CredentialAlreadyExistsError: If credential_id already exists
        """
        pass

    @abstractmethod
    def get_by_id(self, credential_id: str) -> Optional[CredentialData]:
        """
        Get credential by ID (internal UUID).

        Args:
            credential_id: Internal credential ID (UUID)

        Returns:
            Credential data or None if not found
        """
        pass

    @abstractmethod
    def get_by_credential_id(self, credential_id: str) -> Optional[CredentialData]:
        """
        Get credential by WebAuthn credential ID.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID

        Returns:
            Credential data or None if not found
        """
        pass

    @abstractmethod
    def get_by_user(self, user_id: Any, active_only: bool = True) -> List[CredentialData]:
        """
        Get all credentials for a user.

        Args:
            user_id: User ID
            active_only: Only return active credentials

        Returns:
            List of credential data
        """
        pass

    @abstractmethod
    def get_by_user_handle(self, user_handle: str) -> Optional[CredentialData]:
        """
        Get credential by user handle (for discoverable credentials).

        Args:
            user_handle: Base64URL-encoded user handle

        Returns:
            Credential data or None if not found
        """
        pass

    @abstractmethod
    def update_counter(self, credential_id: str, new_count: int) -> bool:
        """
        Update signature counter.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID
            new_count: New counter value

        Returns:
            True if updated successfully, False if counter regression
        """
        pass

    @abstractmethod
    def update_last_used(self, credential_id: str) -> None:
        """
        Update last used timestamp.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID
        """
        pass

    @abstractmethod
    def update_name(self, credential_id: str, name: str) -> None:
        """
        Update credential name.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID
            name: New name
        """
        pass

    @abstractmethod
    def revoke(self, credential_id: str, reason: str = '') -> None:
        """
        Revoke a credential.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID
            reason: Reason for revocation
        """
        pass

    @abstractmethod
    def delete(self, credential_id: str) -> bool:
        """
        Permanently delete a credential.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def count_by_user(self, user_id: Any, active_only: bool = True) -> int:
        """
        Count credentials for a user.

        Args:
            user_id: User ID
            active_only: Only count active credentials

        Returns:
            Number of credentials
        """
        pass

    @abstractmethod
    def exists(self, credential_id: str) -> bool:
        """
        Check if credential exists.

        Args:
            credential_id: Base64URL-encoded WebAuthn credential ID

        Returns:
            True if exists
        """
        pass
