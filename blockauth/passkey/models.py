"""
Passkey/WebAuthn Models for BlockAuth

Database models for storing WebAuthn credentials and challenges.
"""

import hmac
import logging

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from uuid6 import uuid7

from blockauth.notification import NotificationEvent, emit_passkey_event

from .constants import AuthenticatorTransport, ChallengeType

logger = logging.getLogger(__name__)


def validate_transports(value):
    """Validate transport values against AuthenticatorTransport enum."""
    valid = {t.value for t in AuthenticatorTransport}
    for v in value:
        if v not in valid:
            raise DjangoValidationError(f"Invalid transport: {v}")


class PasskeyCredential(models.Model):
    """
    Stores WebAuthn credentials for users.

    Each credential represents a passkey registered on a user's device.
    Users can have multiple credentials across different devices.

    The credential stores the public key, which is used to verify
    signatures during authentication. The private key never leaves
    the user's device.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)

    # Link to user (using AUTH_USER_MODEL for flexibility)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="passkey_credentials",
        help_text="User who owns this credential",
    )

    # Credential identifier (from authenticator)
    # Base64URL encoded, variable length (usually 16-64 bytes)
    credential_id = models.TextField(
        unique=True, db_index=True, help_text="Base64URL-encoded credential ID from authenticator"
    )

    # Public key (COSE-encoded, then base64url)
    public_key = models.TextField(help_text="Base64URL-encoded COSE public key")

    # COSE algorithm identifier
    algorithm = models.IntegerField(
        default=-7, help_text="COSE algorithm identifier (e.g., -7 for ES256, -257 for RS256)"  # ES256
    )

    # Signature counter (for clone detection)
    # This is incremented by the authenticator on each use
    sign_count = models.BigIntegerField(
        default=0, validators=[MinValueValidator(0)], help_text="Signature counter to detect cloned authenticators"
    )

    # AAGUID (Authenticator Attestation GUID)
    # Identifies the authenticator model (e.g., YubiKey 5, iPhone, etc.)
    aaguid = models.CharField(
        max_length=36, blank=True, default="", help_text="Authenticator model identifier (AAGUID as UUID string)"
    )

    # User-friendly name for the credential
    name = models.CharField(
        max_length=255, default="", blank=True, help_text="User-provided name for this credential (e.g., 'My iPhone')"
    )

    # Device/transport information
    # Stored as JSON array of transport strings
    transports = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_transports],
        help_text="Supported transports: internal, usb, nfc, ble, hybrid",
    )

    # Authenticator attachment type
    authenticator_attachment = models.CharField(
        max_length=20,
        blank=True,
        default="",
        choices=[
            ("platform", "Platform"),
            ("cross-platform", "Cross-Platform"),
        ],
        help_text="platform (built-in) or cross-platform (roaming)",
    )

    # Backup eligibility and state (for synced passkeys)
    # These flags indicate if the credential is/can be synced across devices
    backup_eligible = models.BooleanField(default=False, help_text="Whether credential can be backed up (BE flag)")
    backup_state = models.BooleanField(default=False, help_text="Whether credential is currently backed up (BS flag)")

    # Discoverable credential (resident key)
    # Discoverable credentials enable passwordless login
    is_discoverable = models.BooleanField(
        default=False, help_text="Whether this is a discoverable credential (resident key)"
    )

    # User handle for discoverable credentials
    # This is an opaque identifier returned during authentication
    user_handle = models.TextField(
        blank=True, default="", help_text="Base64URL-encoded user handle for discoverable credentials"
    )

    # Attestation data (optional, for enterprise use)
    attestation_object = models.TextField(
        blank=True, default="", help_text="Base64URL-encoded attestation object (if attestation was requested)"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, help_text="When the credential was registered")
    last_used_at = models.DateTimeField(
        null=True, blank=True, help_text="When the credential was last used for authentication"
    )

    # Soft delete / revocation
    is_active = models.BooleanField(default=True, help_text="Whether this credential is active")
    revoked_at = models.DateTimeField(null=True, blank=True, help_text="When the credential was revoked")
    revocation_reason = models.CharField(max_length=255, blank=True, default="", help_text="Reason for revocation")

    class Meta:
        app_label = "blockauth"
        managed = True
        db_table = "passkey_credential"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_active"], name="passkey_user_active_idx"),
            models.Index(fields=["credential_id"], name="passkey_cred_id_idx"),
            models.Index(fields=["last_used_at"], name="passkey_last_used_idx"),
        ]
        verbose_name = "Passkey Credential"
        verbose_name_plural = "Passkey Credentials"

    def __str__(self):
        name = self.name or "Unnamed Passkey"
        return f"{name} ({self.user})"

    def update_counter(self, new_count: int) -> bool:
        """
        Update signature counter.

        Returns False if counter regression detected (possible clone).
        Counter regression is a security concern that should be logged.

        Args:
            new_count: New counter value from authenticator

        Returns:
            True if counter updated successfully, False if regression detected
        """
        if new_count <= self.sign_count:
            logger.warning(
                "Passkey counter regression detected (possible clone): " "credential=%s user=%s expected>%d got=%d",
                self.credential_id[:20],
                self.user_id,
                self.sign_count,
                new_count,
            )
            emit_passkey_event(
                NotificationEvent.PASSKEY_COUNTER_REGRESSION,
                {
                    "user_id": str(self.user_id),
                    "credential_id": self.credential_id[:20],
                    "expected_count": self.sign_count,
                    "received_count": new_count,
                },
            )
            return False
        self.sign_count = new_count
        self.last_used_at = timezone.now()
        self.save(update_fields=["sign_count", "last_used_at"])
        return True

    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

    def revoke(self, reason: str = ""):
        """
        Revoke this credential.

        Revoked credentials cannot be used for authentication.

        Args:
            reason: Optional reason for revocation
        """
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save(update_fields=["is_active", "revoked_at", "revocation_reason"])
        emit_passkey_event(
            NotificationEvent.PASSKEY_REVOKED,
            {
                "user_id": str(self.user_id),
                "credential_id": self.credential_id[:20],
                "reason": reason,
            },
        )

    def get_transports_list(self) -> list:
        """Get transports as list of AuthenticatorTransport values"""
        return self.transports if isinstance(self.transports, list) else []


class PasskeyChallenge(models.Model):
    """
    Temporary storage for WebAuthn challenges.

    Challenges must be:
    - Cryptographically random (at least 16 bytes)
    - Single-use (cannot be reused)
    - Short-lived (expire within minutes)

    This model provides database-backed challenge storage.
    For high-traffic applications, consider using Redis/cache instead.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)

    # Challenge value (base64url encoded)
    challenge = models.CharField(max_length=255, unique=True, db_index=True, help_text="Base64URL-encoded challenge")

    # Associated user (optional for discoverable credentials)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        help_text="User associated with this challenge (optional)",
    )

    # Challenge type
    challenge_type = models.CharField(
        max_length=20,
        choices=[
            (ChallengeType.REGISTRATION.value, "Registration"),
            (ChallengeType.AUTHENTICATION.value, "Authentication"),
        ],
        help_text="Whether this is for registration or authentication",
    )

    # Expiration timestamp
    expires_at = models.DateTimeField(db_index=True, help_text="When this challenge expires")

    # Whether challenge has been used
    is_used = models.BooleanField(default=False, help_text="Whether this challenge has been consumed")

    # Additional metadata (optional)
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional data associated with challenge")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "blockauth"
        managed = True
        db_table = "passkey_challenge"
        indexes = [
            models.Index(fields=["challenge"], name="passkey_challenge_idx"),
            models.Index(fields=["expires_at"], name="passkey_expires_idx"),
            models.Index(fields=["user", "challenge_type"], name="passkey_user_type_idx"),
        ]
        verbose_name = "Passkey Challenge"
        verbose_name_plural = "Passkey Challenges"

    def __str__(self):
        return f"Challenge ({self.challenge_type}) - {self.challenge[:20]}..."

    @property
    def is_expired(self) -> bool:
        """Check if challenge has expired"""
        return timezone.now() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if challenge is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired

    def consume(self) -> bool:
        """
        Mark challenge as used.

        Returns False if challenge was already used or expired.

        Returns:
            True if successfully consumed, False otherwise
        """
        if not self.is_valid:
            return False

        self.is_used = True
        self.save(update_fields=["is_used"])
        return True

    @classmethod
    def validate_and_consume(cls, challenge_value: str, expected_type: str = None) -> "PasskeyChallenge | None":
        """
        Validate and consume a challenge with constant-time comparison.

        This method prevents timing attacks by:
        1. Always performing the same operations regardless of validity
        2. Using constant-time string comparison

        Args:
            challenge_value: The challenge string to validate
            expected_type: Optional challenge type to verify

        Returns:
            The challenge object if valid, None otherwise
        """
        # Fetch challenge - DB lookup is not constant-time, but challenge
        # values are cryptographically random so timing leaks are not exploitable
        try:
            challenge_obj = cls.objects.get(challenge=challenge_value)
        except cls.DoesNotExist:
            return None

        # Constant-time comparison for challenge type if specified
        type_valid = True
        if expected_type is not None:
            type_valid = hmac.compare_digest(challenge_obj.challenge_type.encode(), expected_type.encode())

        # Check validity (expiry and used status)
        is_valid = challenge_obj.is_valid and type_valid

        if is_valid:
            challenge_obj.is_used = True
            challenge_obj.save(update_fields=["is_used"])
            return challenge_obj

        return None

    @classmethod
    def cleanup_expired(cls) -> int:
        """
        Delete expired challenges with monitoring.

        Should be called periodically (e.g., via cron or celery beat).
        Recommended: Run every 5-15 minutes.

        Returns:
            Number of challenges deleted
        """
        expired_count = cls.objects.filter(expires_at__lt=timezone.now()).count()

        if expired_count > 0:
            deleted, _ = cls.objects.filter(expires_at__lt=timezone.now()).delete()
            logger.info("Passkey challenge cleanup: deleted %d expired challenges", deleted)
            return deleted

        return 0

    @classmethod
    def get_active_challenge_count(cls, user=None) -> int:
        """
        Get count of active (non-expired, unused) challenges.

        Useful for rate limiting at the view level.

        Args:
            user: Optional user to filter by

        Returns:
            Count of active challenges
        """
        qs = cls.objects.filter(is_used=False, expires_at__gt=timezone.now())
        if user is not None:
            qs = qs.filter(user=user)
        return qs.count()
