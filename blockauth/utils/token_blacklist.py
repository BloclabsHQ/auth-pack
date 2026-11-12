"""
Refresh Token Blacklist

Cache-backed blacklist that prevents reuse of rotated refresh tokens.
When ``ROTATE_REFRESH_TOKENS`` is enabled (default), each refresh token
can only be exchanged for a new pair once — the old token's ``jti`` is
blacklisted for the remainder of its natural lifetime.

Design decisions:
- Uses Django's cache framework (no extra DB table required).
- Blacklist entries auto-expire when the original token would have expired,
  so the cache doesn't grow unboundedly.
- ``is_blacklisted()`` is intentionally a simple cache lookup (O(1)).
"""

from django.core.cache import cache as default_cache

from blockauth.utils.config import get_config

_BLACKLIST_PREFIX = "jwt_blacklist_"


def blacklist_token(jti: str, remaining_ttl_seconds: int, cache=None) -> None:
    """
    Add a token's ``jti`` to the blacklist.

    Args:
        jti: The JWT ID (``jti`` claim) of the token to blacklist.
        remaining_ttl_seconds: Seconds until the token naturally expires.
            The blacklist entry is kept for this long (plus a small buffer).
        cache: Optional Django cache backend override (useful for testing).
    """
    if not jti:
        return
    _cache = cache or default_cache
    # Keep entry a little longer than the token's remaining life to handle clock skew
    ttl = max(int(remaining_ttl_seconds) + 60, 60)
    _cache.set(f"{_BLACKLIST_PREFIX}{jti}", True, ttl)


def is_blacklisted(jti: str, cache=None) -> bool:
    """
    Check whether a token's ``jti`` has been blacklisted.

    Returns True if the token should be rejected.
    """
    if not jti:
        return False
    _cache = cache or default_cache
    return bool(_cache.get(f"{_BLACKLIST_PREFIX}{jti}"))


_FAMILY_HEAD_PREFIX = "jwt_family_head_"
_FAMILY_REVOKED_PREFIX = "jwt_family_revoked_"


def _ttl(ttl_seconds: int) -> int:
    return max(int(ttl_seconds) + 60, 60)


def remember_family_head(
    family: str,
    jti: str,
    ttl_seconds: int,
    cache=None,
) -> None:
    """Store the current refresh ``jti`` for a family (SEC-02)."""
    if not family or not jti:
        return
    _cache = cache or default_cache
    _cache.set(f"{_FAMILY_HEAD_PREFIX}{family}", jti, _ttl(ttl_seconds))


def is_family_revoked(family: str, cache=None) -> bool:
    """True when the family has been revoked (SEC-02)."""
    if not family:
        return False
    _cache = cache or default_cache
    return bool(_cache.get(f"{_FAMILY_REVOKED_PREFIX}{family}"))


def revoke_family(family: str, cache=None) -> None:
    """Blacklist the current head and reject the family (SEC-02).

    The revoked flag and the head entry last for the full refresh
    lifetime, not the remaining life of the presented token.
    """
    if not family:
        return
    _cache = cache or default_cache
    lifetime = get_config("REFRESH_TOKEN_LIFETIME")
    ttl_seconds = int(lifetime.total_seconds())
    head = _cache.get(f"{_FAMILY_HEAD_PREFIX}{family}")
    if head:
        blacklist_token(head, ttl_seconds, cache=_cache)
    _cache.set(f"{_FAMILY_REVOKED_PREFIX}{family}", True, _ttl(ttl_seconds))
