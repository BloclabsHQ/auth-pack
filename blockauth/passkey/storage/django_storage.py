"""
Django ORM Storage Backend for Passkey Credentials

Implements ICredentialStore using Django ORM and the PasskeyCredential model.
"""

from typing import Optional, List, Any
from django.utils import timezone

from .base import ICredentialStore, CredentialData
from ..models import PasskeyCredential
from ..exceptions import CredentialAlreadyExistsError, CredentialNotFoundError


class DjangoCredentialStore(ICredentialStore):
    """
    Django ORM implementation of credential storage.

    Uses the PasskeyCredential model for database operations.
    """

    def _model_to_data(self, credential: PasskeyCredential) -> CredentialData:
        """Convert Django model to CredentialData"""
        return CredentialData(
            id=str(credential.id),
            user_id=credential.user_id,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            algorithm=credential.algorithm,
            sign_count=credential.sign_count,
            aaguid=credential.aaguid,
            name=credential.name,
            transports=credential.transports or [],
            authenticator_attachment=credential.authenticator_attachment,
            backup_eligible=credential.backup_eligible,
            backup_state=credential.backup_state,
            is_discoverable=credential.is_discoverable,
            user_handle=credential.user_handle,
            attestation_object=credential.attestation_object,
            created_at=credential.created_at,
            last_used_at=credential.last_used_at,
            is_active=credential.is_active,
        )

    def save(self, credential: CredentialData) -> CredentialData:
        """Save a new credential"""
        # Check if credential already exists
        if PasskeyCredential.objects.filter(
            credential_id=credential.credential_id
        ).exists():
            raise CredentialAlreadyExistsError(
                f"Credential with ID {credential.credential_id[:20]}... already exists"
            )

        # Create new credential
        db_credential = PasskeyCredential.objects.create(
            user_id=credential.user_id,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            algorithm=credential.algorithm,
            sign_count=credential.sign_count,
            aaguid=credential.aaguid,
            name=credential.name,
            transports=credential.transports,
            authenticator_attachment=credential.authenticator_attachment,
            backup_eligible=credential.backup_eligible,
            backup_state=credential.backup_state,
            is_discoverable=credential.is_discoverable,
            user_handle=credential.user_handle,
            attestation_object=credential.attestation_object,
        )

        return self._model_to_data(db_credential)

    def get_by_id(self, credential_id: str) -> Optional[CredentialData]:
        """Get credential by internal UUID"""
        try:
            credential = PasskeyCredential.objects.get(id=credential_id)
            return self._model_to_data(credential)
        except PasskeyCredential.DoesNotExist:
            return None

    def get_by_credential_id(self, credential_id: str) -> Optional[CredentialData]:
        """Get credential by WebAuthn credential ID"""
        try:
            credential = PasskeyCredential.objects.get(credential_id=credential_id)
            return self._model_to_data(credential)
        except PasskeyCredential.DoesNotExist:
            return None

    def get_by_user(self, user_id: Any, active_only: bool = True) -> List[CredentialData]:
        """Get all credentials for a user"""
        queryset = PasskeyCredential.objects.filter(user_id=user_id)
        if active_only:
            queryset = queryset.filter(is_active=True)
        return [self._model_to_data(c) for c in queryset.order_by('-created_at')]

    def get_by_user_handle(self, user_handle: str) -> Optional[CredentialData]:
        """Get credential by user handle (for discoverable credentials)"""
        try:
            credential = PasskeyCredential.objects.get(
                user_handle=user_handle,
                is_active=True
            )
            return self._model_to_data(credential)
        except PasskeyCredential.DoesNotExist:
            return None
        except PasskeyCredential.MultipleObjectsReturned:
            # Return the most recently used one
            credential = PasskeyCredential.objects.filter(
                user_handle=user_handle,
                is_active=True
            ).order_by('-last_used_at', '-created_at').first()
            return self._model_to_data(credential) if credential else None

    def update_counter(self, credential_id: str, new_count: int) -> bool:
        """Update signature counter"""
        try:
            credential = PasskeyCredential.objects.get(credential_id=credential_id)
            return credential.update_counter(new_count)
        except PasskeyCredential.DoesNotExist:
            raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

    def update_last_used(self, credential_id: str) -> None:
        """Update last used timestamp"""
        PasskeyCredential.objects.filter(credential_id=credential_id).update(
            last_used_at=timezone.now()
        )

    def update_name(self, credential_id: str, name: str) -> None:
        """Update credential name"""
        updated = PasskeyCredential.objects.filter(credential_id=credential_id).update(
            name=name
        )
        if not updated:
            raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

    def revoke(self, credential_id: str, reason: str = '') -> None:
        """Revoke a credential"""
        try:
            credential = PasskeyCredential.objects.get(credential_id=credential_id)
            credential.revoke(reason)
        except PasskeyCredential.DoesNotExist:
            raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

    def delete(self, credential_id: str) -> bool:
        """Permanently delete a credential"""
        deleted, _ = PasskeyCredential.objects.filter(credential_id=credential_id).delete()
        return deleted > 0

    def count_by_user(self, user_id: Any, active_only: bool = True) -> int:
        """Count credentials for a user"""
        queryset = PasskeyCredential.objects.filter(user_id=user_id)
        if active_only:
            queryset = queryset.filter(is_active=True)
        return queryset.count()

    def exists(self, credential_id: str) -> bool:
        """Check if credential exists"""
        return PasskeyCredential.objects.filter(credential_id=credential_id).exists()
