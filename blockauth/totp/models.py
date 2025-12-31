"""
TOTP 2FA Models for BlockAuth

Database models for storing TOTP secrets, backup codes, and verification state.
"""
import logging
import secrets
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone

from .constants import TOTPStatus

logger = logging.getLogger(__name__)


class TOTP2FA(models.Model):
    """
    Stores TOTP 2FA configuration for users.

    Each user can have one TOTP configuration. The secret is encrypted
    before storage and is used to generate/verify time-based codes.

    Security notes:
    - Secret should be encrypted at rest using application-level encryption
    - Backup codes are hashed (not encrypted) since they're single-use
    - Failed attempt tracking prevents brute-force attacks
    - Last used timestamp prevents code reuse within time window
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    # Link to user (using AUTH_USER_MODEL for flexibility)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='totp_2fa',
        help_text="User who owns this TOTP configuration"
    )

    # Encrypted TOTP secret (Base32-encoded before encryption)
    # Application-level encryption is applied before storage
    encrypted_secret = models.TextField(
        help_text="Encrypted TOTP secret (Base32-encoded internally)"
    )

    # Status of TOTP 2FA
    status = models.CharField(
        max_length=30,
        choices=[
            (TOTPStatus.DISABLED.value, 'Disabled'),
            (TOTPStatus.PENDING_CONFIRMATION.value, 'Pending Confirmation'),
            (TOTPStatus.ENABLED.value, 'Enabled'),
        ],
        default=TOTPStatus.DISABLED.value,
        help_text="Current TOTP status"
    )

    # Algorithm and configuration (stored for verification)
    algorithm = models.CharField(
        max_length=10,
        default='sha1',
        help_text="Hash algorithm (sha1, sha256, sha512)"
    )
    digits = models.PositiveSmallIntegerField(
        default=6,
        help_text="Number of digits in TOTP code (6 or 8)"
    )
    time_step = models.PositiveSmallIntegerField(
        default=30,
        help_text="Time step in seconds"
    )

    # Hashed backup codes (stored as JSON array of hashed codes)
    # Each code is hashed before storage for security
    backup_codes_hash = models.JSONField(
        default=list,
        blank=True,
        help_text="List of hashed backup codes (SHA-256)"
    )
    backup_codes_remaining = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of unused backup codes remaining"
    )

    # Rate limiting / lockout tracking
    failed_attempts = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of consecutive failed verification attempts"
    )
    locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Account is locked until this time due to failed attempts"
    )
    last_failed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of last failed verification"
    )

    # Replay attack prevention
    # Stores the time counter of the last successfully used code
    last_used_counter = models.BigIntegerField(
        null=True,
        blank=True,
        help_text="Time counter of last successfully used code (prevents replay)"
    )
    last_verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When TOTP was last successfully verified"
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When TOTP was initially set up"
    )
    enabled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When TOTP was confirmed and enabled"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Last update timestamp"
    )

    # Recovery tracking
    recovery_email_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When recovery instructions were last sent"
    )

    class Meta:
        app_label = 'blockauth'
        managed = True
        db_table = 'totp_2fa'
        indexes = [
            models.Index(fields=['user'], name='totp_user_idx'),
            models.Index(fields=['status'], name='totp_status_idx'),
            models.Index(fields=['locked_until'], name='totp_locked_idx'),
        ]
        verbose_name = 'TOTP 2FA Configuration'
        verbose_name_plural = 'TOTP 2FA Configurations'

    def __str__(self):
        return f"TOTP 2FA ({self.user}) - {self.status}"

    @property
    def is_enabled(self) -> bool:
        """Check if TOTP is fully enabled."""
        return self.status == TOTPStatus.ENABLED.value

    @property
    def is_pending(self) -> bool:
        """Check if TOTP is pending confirmation."""
        return self.status == TOTPStatus.PENDING_CONFIRMATION.value

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked due to failed attempts."""
        if self.locked_until is None:
            return False
        return timezone.now() < self.locked_until

    @property
    def lockout_remaining_seconds(self) -> int:
        """Get remaining lockout time in seconds."""
        if not self.is_locked:
            return 0
        delta = self.locked_until - timezone.now()
        return max(0, int(delta.total_seconds()))

    def enable(self) -> None:
        """Mark TOTP as enabled after successful confirmation."""
        self.status = TOTPStatus.ENABLED.value
        self.enabled_at = timezone.now()
        self.failed_attempts = 0
        self.locked_until = None
        self.save(update_fields=['status', 'enabled_at', 'failed_attempts', 'locked_until', 'updated_at'])
        logger.info("TOTP enabled for user %s", self.user_id)

    def disable(self) -> None:
        """Disable TOTP 2FA."""
        self.status = TOTPStatus.DISABLED.value
        self.encrypted_secret = ''
        self.backup_codes_hash = []
        self.backup_codes_remaining = 0
        self.failed_attempts = 0
        self.locked_until = None
        self.last_used_counter = None
        self.save()
        logger.info("TOTP disabled for user %s", self.user_id)

    def record_failed_attempt(self, max_attempts: int = 5, lockout_duration: int = 300) -> None:
        """
        Record a failed verification attempt.

        Args:
            max_attempts: Maximum allowed attempts before lockout
            lockout_duration: Lockout duration in seconds
        """
        self.failed_attempts += 1
        self.last_failed_at = timezone.now()

        if self.failed_attempts >= max_attempts:
            self.locked_until = timezone.now() + timezone.timedelta(seconds=lockout_duration)
            logger.warning(
                "TOTP account locked for user %s until %s (failed attempts: %d)",
                self.user_id, self.locked_until, self.failed_attempts
            )

        self.save(update_fields=['failed_attempts', 'last_failed_at', 'locked_until', 'updated_at'])

    def record_successful_verification(self, time_counter: int) -> None:
        """
        Record a successful verification.

        Args:
            time_counter: The time counter value of the verified code
        """
        self.failed_attempts = 0
        self.locked_until = None
        self.last_used_counter = time_counter
        self.last_verified_at = timezone.now()
        self.save(update_fields=[
            'failed_attempts', 'locked_until', 'last_used_counter',
            'last_verified_at', 'updated_at'
        ])

    def is_counter_used(self, time_counter: int) -> bool:
        """
        Check if a time counter has already been used (replay prevention).

        Args:
            time_counter: The time counter to check

        Returns:
            True if counter was already used, False otherwise
        """
        if self.last_used_counter is None:
            return False
        return time_counter <= self.last_used_counter

    def use_backup_code(self, code_index: int) -> None:
        """
        Mark a backup code as used.

        Args:
            code_index: Index of the code in backup_codes_hash list
        """
        if 0 <= code_index < len(self.backup_codes_hash):
            # Replace with empty string to mark as used while preserving indices
            self.backup_codes_hash[code_index] = ''
            self.backup_codes_remaining = max(0, self.backup_codes_remaining - 1)
            self.save(update_fields=['backup_codes_hash', 'backup_codes_remaining', 'updated_at'])
            logger.info(
                "Backup code used for user %s (remaining: %d)",
                self.user_id, self.backup_codes_remaining
            )

    def has_backup_codes(self) -> bool:
        """Check if user has unused backup codes available."""
        return self.backup_codes_remaining > 0


class TOTPVerificationLog(models.Model):
    """
    Audit log for TOTP verification attempts.

    Useful for security monitoring and incident investigation.
    Can be cleaned up periodically to manage storage.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    # Link to user
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='totp_verification_logs',
        help_text="User who attempted verification"
    )

    # Verification result
    success = models.BooleanField(
        help_text="Whether verification was successful"
    )
    verification_type = models.CharField(
        max_length=20,
        choices=[
            ('totp', 'TOTP Code'),
            ('backup', 'Backup Code'),
        ],
        help_text="Type of code verified"
    )

    # Request context
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address of the request"
    )
    user_agent = models.TextField(
        blank=True,
        default='',
        help_text="User agent of the request"
    )

    # Failure details (for failed attempts)
    failure_reason = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text="Reason for failure if applicable"
    )

    # Timestamp
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="When the verification attempt occurred"
    )

    class Meta:
        app_label = 'blockauth'
        managed = True
        db_table = 'totp_verification_log'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at'], name='totp_log_user_time_idx'),
            models.Index(fields=['success', 'created_at'], name='totp_log_success_idx'),
            models.Index(fields=['ip_address', 'created_at'], name='totp_log_ip_idx'),
        ]
        verbose_name = 'TOTP Verification Log'
        verbose_name_plural = 'TOTP Verification Logs'

    def __str__(self):
        status = 'success' if self.success else 'failed'
        return f"TOTP {self.verification_type} ({status}) - {self.user} at {self.created_at}"

    @classmethod
    def log_verification(
        cls,
        user,
        success: bool,
        verification_type: str = 'totp',
        ip_address: str = None,
        user_agent: str = '',
        failure_reason: str = ''
    ) -> 'TOTPVerificationLog':
        """
        Create a verification log entry.

        Args:
            user: User who attempted verification
            success: Whether verification was successful
            verification_type: 'totp' or 'backup'
            ip_address: IP address of the request
            user_agent: User agent string
            failure_reason: Reason for failure if applicable

        Returns:
            Created log entry
        """
        return cls.objects.create(
            user=user,
            success=success,
            verification_type=verification_type,
            ip_address=ip_address,
            user_agent=user_agent[:1024] if user_agent else '',  # Truncate long user agents
            failure_reason=failure_reason
        )

    @classmethod
    def cleanup_old_logs(cls, days: int = 90) -> int:
        """
        Delete logs older than specified days.

        Args:
            days: Number of days to retain logs

        Returns:
            Number of logs deleted
        """
        cutoff = timezone.now() - timezone.timedelta(days=days)
        deleted, _ = cls.objects.filter(created_at__lt=cutoff).delete()
        if deleted > 0:
            logger.info("TOTP verification log cleanup: deleted %d old entries", deleted)
        return deleted
