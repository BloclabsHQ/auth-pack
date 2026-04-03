"""
Django ORM Storage Implementation for TOTP 2FA

Provides Django model-based storage for TOTP 2FA data.
"""

import logging
from typing import Any, List, Optional

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from ..constants import TOTPStatus
from ..exceptions import TOTPAlreadyEnabledError, TOTPStorageError
from ..models import TOTP2FA, TOTPVerificationLog
from .base import ITOTP2FAStore, TOTP2FAData

logger = logging.getLogger(__name__)


class DjangoTOTP2FAStore(ITOTP2FAStore):
    """
    Django ORM implementation of TOTP 2FA storage.

    Uses the TOTP2FA and TOTPVerificationLog models for persistence.
    """

    def _model_to_data(self, totp: TOTP2FA) -> TOTP2FAData:
        """Convert Django model to data object."""
        return TOTP2FAData(
            user_id=str(totp.user_id),
            encrypted_secret=totp.encrypted_secret,
            status=totp.status,
            algorithm=totp.algorithm,
            digits=totp.digits,
            time_step=totp.time_step,
            backup_codes_hash=totp.backup_codes_hash or [],
            backup_codes_remaining=totp.backup_codes_remaining,
            failed_attempts=totp.failed_attempts,
            locked_until=totp.locked_until,
            last_used_counter=totp.last_used_counter,
            last_verified_at=totp.last_verified_at,
            created_at=totp.created_at,
            enabled_at=totp.enabled_at,
        )

    def get_by_user_id(self, user_id: str) -> Optional[TOTP2FAData]:
        """Get TOTP configuration for a user."""
        try:
            totp = TOTP2FA.objects.get(user_id=user_id)
            return self._model_to_data(totp)
        except TOTP2FA.DoesNotExist:
            return None
        except Exception as e:
            logger.error("Error fetching TOTP for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to fetch TOTP data: {e}")

    def get_model_by_user_id(self, user_id: str) -> Optional[TOTP2FA]:
        """Get the Django model directly (internal use)."""
        try:
            return TOTP2FA.objects.get(user_id=user_id)
        except TOTP2FA.DoesNotExist:
            return None

    @transaction.atomic
    def create(
        self,
        user_id: str,
        encrypted_secret: str,
        algorithm: str = "sha1",
        digits: int = 6,
        time_step: int = 30,
        status: str = "pending_confirmation",
    ) -> TOTP2FAData:
        """Create a new TOTP configuration."""
        # Check if already exists
        existing = self.get_by_user_id(user_id)
        if existing and existing.status != TOTPStatus.DISABLED.value:
            raise TOTPAlreadyEnabledError()

        try:
            # Get user model
            User = get_user_model()
            user = User.objects.get(pk=user_id)

            # Delete existing disabled config if any
            if existing:
                TOTP2FA.objects.filter(user_id=user_id).delete()

            # Create new config
            totp = TOTP2FA.objects.create(
                user=user,
                encrypted_secret=encrypted_secret,
                status=status,
                algorithm=algorithm,
                digits=digits,
                time_step=time_step,
            )

            logger.info("TOTP created for user %s with status %s", user_id, status)
            return self._model_to_data(totp)

        except Exception as e:
            logger.error("Error creating TOTP for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to create TOTP: {e}")

    @transaction.atomic
    def update_status(self, user_id: str, status: str) -> bool:
        """Update TOTP status."""
        try:
            updated = TOTP2FA.objects.filter(user_id=user_id).update(
                status=status,
                enabled_at=timezone.now() if status == TOTPStatus.ENABLED.value else None,
                updated_at=timezone.now(),
            )
            if updated:
                logger.info("TOTP status updated for user %s: %s", user_id, status)
            return updated > 0
        except Exception as e:
            logger.error("Error updating TOTP status for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to update TOTP status: {e}")

    @transaction.atomic
    def delete(self, user_id: str) -> bool:
        """Delete TOTP configuration for a user."""
        try:
            deleted, _ = TOTP2FA.objects.filter(user_id=user_id).delete()
            if deleted:
                logger.info("TOTP deleted for user %s", user_id)
            return deleted > 0
        except Exception as e:
            logger.error("Error deleting TOTP for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to delete TOTP: {e}")

    @transaction.atomic
    def set_backup_codes(self, user_id: str, hashed_codes: List[str]) -> bool:
        """Set backup codes for a user."""
        try:
            updated = TOTP2FA.objects.filter(user_id=user_id).update(
                backup_codes_hash=hashed_codes, backup_codes_remaining=len(hashed_codes), updated_at=timezone.now()
            )
            if updated:
                logger.info("Backup codes set for user %s: %d codes", user_id, len(hashed_codes))
            return updated > 0
        except Exception as e:
            logger.error("Error setting backup codes for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to set backup codes: {e}")

    def use_backup_code(self, user_id: str, code_index: int) -> bool:
        """Mark a backup code as used."""
        try:
            totp = self.get_model_by_user_id(user_id)
            if totp is None:
                return False

            totp.use_backup_code(code_index)
            return True
        except Exception as e:
            logger.error("Error using backup code for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to use backup code: {e}")

    def record_failed_attempt(self, user_id: str, max_attempts: int = 5, lockout_duration: int = 300) -> bool:
        """Record a failed verification attempt."""
        try:
            totp = self.get_model_by_user_id(user_id)
            if totp is None:
                return False

            totp.record_failed_attempt(max_attempts, lockout_duration)
            return totp.is_locked
        except Exception as e:
            logger.error("Error recording failed attempt for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to record failed attempt: {e}")

    def record_successful_verification(self, user_id: str, time_counter: int) -> bool:
        """Record a successful verification."""
        try:
            totp = self.get_model_by_user_id(user_id)
            if totp is None:
                return False

            totp.record_successful_verification(time_counter)
            return True
        except Exception as e:
            logger.error("Error recording successful verification for user %s: %s", user_id, e)
            raise TOTPStorageError(f"Failed to record successful verification: {e}")

    def is_counter_used(self, user_id: str, time_counter: int) -> bool:
        """Check if a time counter has been used."""
        try:
            totp = self.get_model_by_user_id(user_id)
            if totp is None:
                return False
            return totp.is_counter_used(time_counter)
        except Exception as e:
            logger.error("Error checking counter for user %s: %s", user_id, e)
            return False

    def log_verification(
        self,
        user_id: str,
        success: bool,
        verification_type: str = "totp",
        ip_address: Optional[str] = None,
        user_agent: str = "",
        failure_reason: str = "",
    ) -> None:
        """Log a verification attempt."""
        try:
            User = get_user_model()
            user = User.objects.get(pk=user_id)

            TOTPVerificationLog.log_verification(
                user=user,
                success=success,
                verification_type=verification_type,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason=failure_reason,
            )
        except Exception as e:
            # Don't raise on logging failures
            logger.warning("Failed to log TOTP verification for user %s: %s", user_id, e)

    def get_user(self, user_id: str) -> Optional[Any]:
        """Get user object by ID."""
        try:
            User = get_user_model()
            return User.objects.get(pk=user_id)
        except Exception:
            return None
