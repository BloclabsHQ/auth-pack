"""
In-Memory Storage Backend for Passkey Credentials

Implements ICredentialStore using in-memory dictionary storage.
Useful for testing and development.

WARNING: This storage is NOT persistent. All data is lost when the
application restarts. Use only for testing purposes.
"""

from uuid6 import uuid7
from typing import Optional, List, Any, Dict
from datetime import datetime
from threading import Lock

from .base import ICredentialStore, CredentialData
from ..exceptions import CredentialAlreadyExistsError, CredentialNotFoundError


class MemoryCredentialStore(ICredentialStore):
    """
    In-memory implementation of credential storage.

    Stores credentials in a dictionary. Thread-safe.

    Usage:
        store = MemoryCredentialStore()
        # Use for testing...

        # Clear all data
        store.clear()
    """

    _instance: Optional['MemoryCredentialStore'] = None
    _lock = Lock()

    def __new__(cls):
        """Singleton pattern for shared memory across tests"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._credentials: Dict[str, CredentialData] = {}
                    cls._instance._by_credential_id: Dict[str, str] = {}
                    cls._instance._by_user_handle: Dict[str, str] = {}
        return cls._instance

    def clear(self):
        """Clear all stored credentials (for testing)"""
        with self._lock:
            self._credentials.clear()
            self._by_credential_id.clear()
            self._by_user_handle.clear()

    def save(self, credential: CredentialData) -> CredentialData:
        """Save a new credential"""
        with self._lock:
            # Check if credential already exists
            if credential.credential_id in self._by_credential_id:
                raise CredentialAlreadyExistsError(
                    f"Credential with ID {credential.credential_id[:20]}... already exists"
                )

            # Generate ID if not set
            if not credential.id:
                credential.id = str(uuid7())

            # Set timestamps if not set
            if not credential.created_at:
                credential.created_at = datetime.utcnow()

            # Store credential
            self._credentials[credential.id] = credential
            self._by_credential_id[credential.credential_id] = credential.id

            # Index by user handle if discoverable
            if credential.user_handle:
                self._by_user_handle[credential.user_handle] = credential.id

            return credential

    def get_by_id(self, credential_id: str) -> Optional[CredentialData]:
        """Get credential by internal UUID"""
        return self._credentials.get(credential_id)

    def get_by_credential_id(self, credential_id: str) -> Optional[CredentialData]:
        """Get credential by WebAuthn credential ID"""
        internal_id = self._by_credential_id.get(credential_id)
        if internal_id:
            return self._credentials.get(internal_id)
        return None

    def get_by_user(self, user_id: Any, active_only: bool = True) -> List[CredentialData]:
        """Get all credentials for a user"""
        results = []
        for credential in self._credentials.values():
            if credential.user_id == user_id:
                if not active_only or credential.is_active:
                    results.append(credential)
        # Sort by created_at descending
        results.sort(key=lambda c: c.created_at or datetime.min, reverse=True)
        return results

    def get_by_user_handle(self, user_handle: str) -> Optional[CredentialData]:
        """Get credential by user handle (for discoverable credentials)"""
        internal_id = self._by_user_handle.get(user_handle)
        if internal_id:
            credential = self._credentials.get(internal_id)
            if credential and credential.is_active:
                return credential
        return None

    def update_counter(self, credential_id: str, new_count: int) -> bool:
        """Update signature counter"""
        with self._lock:
            internal_id = self._by_credential_id.get(credential_id)
            if not internal_id:
                raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

            credential = self._credentials.get(internal_id)
            if not credential:
                raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

            # Check for counter regression
            if new_count <= credential.sign_count:
                return False

            # Update counter and last used
            credential.sign_count = new_count
            credential.last_used_at = datetime.utcnow()
            return True

    def update_last_used(self, credential_id: str) -> None:
        """Update last used timestamp"""
        with self._lock:
            internal_id = self._by_credential_id.get(credential_id)
            if internal_id and internal_id in self._credentials:
                self._credentials[internal_id].last_used_at = datetime.utcnow()

    def update_name(self, credential_id: str, name: str) -> None:
        """Update credential name"""
        with self._lock:
            internal_id = self._by_credential_id.get(credential_id)
            if not internal_id or internal_id not in self._credentials:
                raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")
            self._credentials[internal_id].name = name

    def revoke(self, credential_id: str, reason: str = '') -> None:
        """Revoke a credential"""
        with self._lock:
            internal_id = self._by_credential_id.get(credential_id)
            if not internal_id or internal_id not in self._credentials:
                raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

            credential = self._credentials[internal_id]
            credential.is_active = False

    def delete(self, credential_id: str) -> bool:
        """Permanently delete a credential"""
        with self._lock:
            internal_id = self._by_credential_id.get(credential_id)
            if not internal_id:
                return False

            credential = self._credentials.get(internal_id)
            if credential:
                # Remove from indices
                if credential.user_handle:
                    self._by_user_handle.pop(credential.user_handle, None)
                self._by_credential_id.pop(credential_id, None)
                del self._credentials[internal_id]
                return True
            return False

    def count_by_user(self, user_id: Any, active_only: bool = True) -> int:
        """Count credentials for a user"""
        count = 0
        for credential in self._credentials.values():
            if credential.user_id == user_id:
                if not active_only or credential.is_active:
                    count += 1
        return count

    def exists(self, credential_id: str) -> bool:
        """Check if credential exists"""
        return credential_id in self._by_credential_id
