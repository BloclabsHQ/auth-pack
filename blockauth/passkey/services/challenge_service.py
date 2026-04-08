"""
Challenge Service for Passkey/WebAuthn

Handles generation, storage, and validation of WebAuthn challenges.
Challenges must be cryptographically random, single-use, and short-lived.
"""

from datetime import timedelta
from typing import Any, Optional

from django.utils import timezone

from ..config import get_passkey_config
from ..constants import ChallengeType
from ..exceptions import ChallengeAlreadyUsedError, ChallengeExpiredError
from ..models import PasskeyChallenge
from ..utils import base64url_encode, generate_challenge


class ChallengeService:
    """
    Service for managing WebAuthn challenges.

    Challenges are:
    - Cryptographically random (default 32 bytes)
    - Single-use (consumed after verification)
    - Short-lived (default 5 minutes)
    """

    def __init__(self):
        self._config = get_passkey_config()

    def generate(
        self, challenge_type: ChallengeType, user_id: Optional[Any] = None, metadata: Optional[dict] = None
    ) -> str:
        """
        Generate a new challenge.

        Args:
            challenge_type: Type of challenge (registration or authentication)
            user_id: Optional user ID to associate with challenge
            metadata: Optional metadata to store with challenge

        Returns:
            Base64URL-encoded challenge string
        """
        # Generate random bytes
        challenge_bytes = generate_challenge(self._config.challenge_length)
        challenge_b64 = base64url_encode(challenge_bytes)

        # Calculate expiration
        expires_at = timezone.now() + timedelta(seconds=self._config.challenge_expiry)

        # Store challenge
        PasskeyChallenge.objects.create(
            challenge=challenge_b64,
            user_id=user_id,
            challenge_type=challenge_type.value if isinstance(challenge_type, ChallengeType) else challenge_type,
            expires_at=expires_at,
            metadata=metadata or {},
        )

        return challenge_b64

    def validate(
        self,
        challenge: str,
        expected_type: Optional[ChallengeType] = None,
        user_id: Optional[Any] = None,
        consume: bool = True,
    ) -> bool:
        """
        Validate a challenge.

        Args:
            challenge: Base64URL-encoded challenge to validate
            expected_type: Expected challenge type (optional)
            user_id: Expected user ID (optional)
            consume: Whether to mark challenge as used

        Returns:
            True if valid

        Raises:
            ChallengeExpiredError: If challenge has expired
            ChallengeAlreadyUsedError: If challenge was already used
        """
        try:
            challenge_obj = PasskeyChallenge.objects.get(challenge=challenge)
        except PasskeyChallenge.DoesNotExist:
            raise ChallengeExpiredError("Challenge not found or expired")

        # Check if already used
        if challenge_obj.is_used:
            raise ChallengeAlreadyUsedError()

        # Check if expired
        if challenge_obj.is_expired:
            raise ChallengeExpiredError()

        # Check type if specified
        if expected_type is not None:
            expected_type_str = expected_type.value if isinstance(expected_type, ChallengeType) else expected_type
            if challenge_obj.challenge_type != expected_type_str:
                raise ChallengeExpiredError(
                    f"Invalid challenge type. Expected {expected_type_str}, got {challenge_obj.challenge_type}"
                )

        # Check user if specified
        if user_id is not None and challenge_obj.user_id is not None:
            if str(challenge_obj.user_id) != str(user_id):
                raise ChallengeExpiredError("Challenge user mismatch")

        # Consume challenge if requested
        if consume:
            challenge_obj.consume()

        return True

    def get_metadata(self, challenge: str) -> Optional[dict]:
        """
        Get metadata associated with a challenge.

        Args:
            challenge: Base64URL-encoded challenge

        Returns:
            Metadata dict or None if not found
        """
        try:
            challenge_obj = PasskeyChallenge.objects.get(challenge=challenge)
            return challenge_obj.metadata
        except PasskeyChallenge.DoesNotExist:
            return None

    def invalidate(self, challenge: str) -> bool:
        """
        Invalidate a challenge without consuming it.

        Args:
            challenge: Base64URL-encoded challenge

        Returns:
            True if invalidated
        """
        deleted, _ = PasskeyChallenge.objects.filter(challenge=challenge).delete()
        return deleted > 0

    def invalidate_all_for_user(self, user_id: Any) -> int:
        """
        Invalidate all challenges for a user.

        Args:
            user_id: User ID

        Returns:
            Number of challenges invalidated
        """
        deleted, _ = PasskeyChallenge.objects.filter(user_id=user_id).delete()
        return deleted

    def cleanup_expired(self) -> int:
        """
        Delete all expired challenges.

        Should be called periodically (e.g., via cron or celery beat).

        Returns:
            Number of challenges deleted
        """
        return PasskeyChallenge.cleanup_expired()

    def get_challenge_data(self, challenge: str) -> Optional[dict]:
        """
        Get full challenge data.

        Args:
            challenge: Base64URL-encoded challenge

        Returns:
            Challenge data dict or None
        """
        try:
            challenge_obj = PasskeyChallenge.objects.get(challenge=challenge)
            return {
                "challenge": challenge_obj.challenge,
                "user_id": challenge_obj.user_id,
                "challenge_type": challenge_obj.challenge_type,
                "expires_at": challenge_obj.expires_at,
                "is_used": challenge_obj.is_used,
                "metadata": challenge_obj.metadata,
                "created_at": challenge_obj.created_at,
            }
        except PasskeyChallenge.DoesNotExist:
            return None
