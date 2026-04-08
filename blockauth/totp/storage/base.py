"""
TOTP 2FA Storage Interface

Abstract base class defining the storage interface for TOTP 2FA data.
This allows for pluggable storage backends (Django ORM, custom, etc).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional


@dataclass
class TOTP2FAData:
    """
    Data transfer object for TOTP 2FA information.

    This provides a storage-agnostic representation of TOTP data.
    """

    user_id: str
    encrypted_secret: str
    status: str
    algorithm: str = "sha1"
    digits: int = 6
    time_step: int = 30
    backup_codes_hash: List[str] = field(default_factory=list)
    backup_codes_remaining: int = 0
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_used_counter: Optional[int] = None
    last_verified_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    enabled_at: Optional[datetime] = None

    def is_enabled(self) -> bool:
        """Check if TOTP is enabled."""
        return self.status == "enabled"

    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until is None:
            return False
        return datetime.now(tz=self.locked_until.tzinfo) < self.locked_until


class ITOTP2FAStore(ABC):
    """
    Abstract storage interface for TOTP 2FA.

    Implementations must handle:
    - CRUD operations for TOTP configuration
    - Backup codes management
    - Rate limiting state
    - Verification logging (optional)
    """

    @abstractmethod
    def get_by_user_id(self, user_id: str) -> Optional[TOTP2FAData]:
        """
        Get TOTP configuration for a user.

        Args:
            user_id: User identifier

        Returns:
            TOTP2FAData if exists, None otherwise
        """

    @abstractmethod
    def create(
        self,
        user_id: str,
        encrypted_secret: str,
        algorithm: str = "sha1",
        digits: int = 6,
        time_step: int = 30,
        status: str = "pending_confirmation",
    ) -> TOTP2FAData:
        """
        Create a new TOTP configuration.

        Args:
            user_id: User identifier
            encrypted_secret: Encrypted TOTP secret
            algorithm: Hash algorithm (sha1, sha256, sha512)
            digits: Number of digits (6 or 8)
            time_step: Time step in seconds
            status: Initial status

        Returns:
            Created TOTP2FAData

        Raises:
            TOTPAlreadyEnabledError: If TOTP already exists for user
        """

    @abstractmethod
    def update_status(self, user_id: str, status: str) -> bool:
        """
        Update TOTP status.

        Args:
            user_id: User identifier
            status: New status value

        Returns:
            True if updated successfully
        """

    @abstractmethod
    def delete(self, user_id: str) -> bool:
        """
        Delete TOTP configuration for a user.

        Args:
            user_id: User identifier

        Returns:
            True if deleted successfully
        """

    @abstractmethod
    def set_backup_codes(self, user_id: str, hashed_codes: List[str]) -> bool:
        """
        Set backup codes for a user.

        Args:
            user_id: User identifier
            hashed_codes: List of hashed backup codes

        Returns:
            True if set successfully
        """

    @abstractmethod
    def use_backup_code(self, user_id: str, code_index: int) -> bool:
        """
        Mark a backup code as used.

        Args:
            user_id: User identifier
            code_index: Index of the code to mark as used

        Returns:
            True if marked successfully
        """

    @abstractmethod
    def record_failed_attempt(self, user_id: str, max_attempts: int = 5, lockout_duration: int = 300) -> bool:
        """
        Record a failed verification attempt.

        Args:
            user_id: User identifier
            max_attempts: Max attempts before lockout
            lockout_duration: Lockout duration in seconds

        Returns:
            True if account is now locked
        """

    @abstractmethod
    def record_successful_verification(self, user_id: str, time_counter: int) -> bool:
        """
        Record a successful verification.

        Args:
            user_id: User identifier
            time_counter: Time counter of the verified code

        Returns:
            True if recorded successfully
        """

    @abstractmethod
    def is_counter_used(self, user_id: str, time_counter: int) -> bool:
        """
        Check if a time counter has been used (replay prevention).

        Args:
            user_id: User identifier
            time_counter: Time counter to check

        Returns:
            True if counter was already used
        """

    @abstractmethod
    def log_verification(
        self,
        user_id: str,
        success: bool,
        verification_type: str = "totp",
        ip_address: Optional[str] = None,
        user_agent: str = "",
        failure_reason: str = "",
    ) -> None:
        """
        Log a verification attempt.

        Args:
            user_id: User identifier
            success: Whether verification succeeded
            verification_type: 'totp' or 'backup'
            ip_address: Client IP address
            user_agent: Client user agent
            failure_reason: Reason for failure if applicable
        """

    def get_user(self, user_id: str) -> Optional[Any]:
        """
        Get user object by ID.

        Optional method for implementations that need user objects.

        Args:
            user_id: User identifier

        Returns:
            User object or None
        """
        return None
