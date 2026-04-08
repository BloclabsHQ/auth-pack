"""
Passkey Cleanup Service

Service layer for cleaning up expired passkey data.
Can be imported and used by consuming applications (e.g., fabric-auth management commands).

Usage:
    from blockauth.passkey.services import cleanup_expired_challenges, cleanup_all

    # In a management command or scheduled task:
    results = cleanup_all(used_challenge_retention_hours=24)
"""

import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)


def cleanup_expired_challenges() -> dict:
    """
    Delete expired passkey challenges.

    Returns:
        dict with cleanup results
    """
    from blockauth.passkey.models import PasskeyChallenge

    now = timezone.now()
    expired_qs = PasskeyChallenge.objects.filter(expires_at__lt=now)
    count = expired_qs.count()

    if count > 0:
        expired_qs.delete()
        logger.info("Deleted %d expired passkey challenges", count)

    return {"expired_challenges_deleted": count}


def cleanup_used_challenges(older_than_hours: int = 24) -> dict:
    """
    Delete used challenges older than specified hours.

    Args:
        older_than_hours: Delete used challenges older than this many hours

    Returns:
        dict with cleanup results
    """
    from blockauth.passkey.models import PasskeyChallenge

    cutoff = timezone.now() - timedelta(hours=older_than_hours)
    used_qs = PasskeyChallenge.objects.filter(is_used=True, created_at__lt=cutoff)
    count = used_qs.count()

    if count > 0:
        used_qs.delete()
        logger.info("Deleted %d used passkey challenges older than %d hours", count, older_than_hours)

    return {"used_challenges_deleted": count}


def cleanup_all(used_challenge_retention_hours: int = 24) -> dict:
    """
    Run all passkey cleanup tasks.

    Args:
        used_challenge_retention_hours: Keep used challenges for this many hours

    Returns:
        dict with all cleanup results
    """
    results = {}
    results.update(cleanup_expired_challenges())
    results.update(cleanup_used_challenges(used_challenge_retention_hours))

    logger.info("Passkey cleanup completed: %s", results)
    return results
